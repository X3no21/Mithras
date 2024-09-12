var separators = {
    'cls': ['<CLS>', '</CLS>'],
    'met': ['<MET>', '</MET>'],
    'par': ['<PARS>', '</PARS>'],
    'new_par': '<NEWPAR>',
    'ret': ['<RETTYPE>', '</RETTYPE>'],
    'next_entry': '<NEXT_ENTRY>',
    'new_class_field': '<NEW_CLS_FIELD>',
    'class_field': ['<CLS_FIELD>', '</CLS_FIELD>'],
    'field_name': ['<NAME>', '</NAME>'],
    'field_value': ['<VAL>', '</VAL>'],
    'time': ['<TIMESTAMP>', '</TIMESTAMP>'],
    'pkg_name': ['<PKG>', '</PKG>']
};

function methodToString(cls, method, params, ret, pkgName) {
    return separators['cls'][0] + cls + separators['cls'][1] +
        separators['met'][0] + method + separators['met'][1] +
        separators['par'][0] + params.join(separators['new_par']) + separators['par'][1] +
        separators['ret'][0] + ret + separators['ret'][1] +
        separators['time'][0] + Date.now() + separators['time'][1] +
        separators['pkg_name'][0] + pkgName + separators['pkg_name'][1];
}

function isInstanceOfHNAPObject(obj) {
    var HNAPObject = Java.use('com.dlink.router.hnap.data.HNAPObject');
    var currentClass = Java.use(obj.$className);
    while (currentClass !== null) {
        if (currentClass.$className === HNAPObject.$className) {
            return { isHNAPObject: true, className: obj.$className };
        }
        currentClass = currentClass.$superClass;
    }
    return { isHNAPObject: false, className: null };
}

function sendStringFields(obj, objName, hooking) {
    var fields = obj.getClass().getDeclaredFields();
    var fieldData = { className: objName };
    fields.forEach(function (field) {
        field.setAccessible(true);
        var value;
        if ((field.getModifiers() & Java.use("java.lang.reflect.Modifier").STATIC) !== 0) {
            value = field.get(null);
        } else {
            value = field.get(obj);
        }
        if (value !== null && value.getClass().getName() === "java.lang.String") {
            fieldData[field.getName()] = value;
        }
    });
    send({tag: "PARAMETERS", sink: hooking, payload: JSON.stringify(fieldData)});
}

function setStringField(obj, fieldName, newValue) {
    try {
        var field = obj.getClass().getDeclaredField(fieldName);
        field.setAccessible(true);
        field.set(obj, newValue);
    } catch (e) {
        console.log("Field " + fieldName + " not found: " + e.message);
    }
}

function callMethod(overload, clx, args, isStatic) {
    return overload.apply(isStatic ? clx : this, args);
}

function hookSinkMethods(pkgName, methods_to_hook) {
    setImmediate(function () {
        Java.perform(function () {
            for (const hooking in methods_to_hook) {
                let cls = methods_to_hook[hooking]['cls'];
                let method = methods_to_hook[hooking]['method'];
                let params = methods_to_hook[hooking]['params'];
                let ret = methods_to_hook[hooking]['ret'];

                try {
                    let clx = Java.use(cls);
                    if (clx !== undefined && clx[method] !== undefined) {
                        let isStatic = clx[method].isStatic;

                        let overloads = clx[method].overloads;
                        let overload_index = -1;
                        let str_params = "(" + params.join(", ") + ")";
                        for (let i = 0; i < overloads.length; i++) {
                            if (overloads[i].toString().includes(str_params)) {
                                overload_index = i;
                            }
                        }
                        overloads[overload_index].implementation = function () {
                            let suitable_argument;
                            let args = Array.prototype.slice.call(arguments);
                            let is_sink_method = false;

                            for (let i = 0; i < methods_to_hook[hooking]["type"].length; i++) {
                                if (methods_to_hook[hooking]["type"][i] === "SINK") {
                                    is_sink_method = true;
                                    for (let j = 0; j < args.length; j++) {
                                        let hnapCheck = isInstanceOfHNAPObject(args[j]);
                                        if (hnapCheck.isHNAPObject) {
                                            suitable_argument = args[j];
                                            sendStringFields(args[j], hnapCheck.className, hooking);
                                            break;
                                        }
                                    }
                                }
                                send({
                                    tag: "CALLED",
                                    payload: methods_to_hook[hooking]["type"][i] + hooking + separators['time'][0]
                                        + Date.now() + separators['time'][1]
                                });
                            }

                            if (is_sink_method) {
                                recv(function (data_to_modify) {
                                    setStringField(suitable_argument, data_to_modify["field_name"], data_to_modify["field_value"]);
                                }).wait();
                            }

                            if (ret !== 'void') {
                                try {
                                    return callMethod.call(this, overloads[overload_index], clx, args, isStatic);
                                } catch (error) {
                                    let errored = methodToString(cls, method, params, ret, pkgName);
                                    send({ tag: "ERROR", payload: errored });
                                    console.error(`Return error: ${error.toString()} in ${hooking}`);
                                    console.error(error.stack);
                                }
                            } else {
                                try {
                                    callMethod.call(this, overloads[overload_index], clx, args, isStatic);
                                } catch (error) {
                                    let errored = methodToString(cls, method, params, ret, pkgName);
                                    send({ tag: "ERROR", payload: errored });
                                    console.error(`Void method error: ${error.toString()} in ${hooking}`);
                                    console.error(error.stack);
                                }
                            }
                        };
                    }
                } catch (error) {
                    let errored = methodToString(cls, method, params, ret, pkgName);
                    send({ tag: "ERROR", payload: errored });
                    console.error("OOPS: " + error.toString() + ' ' + errored);
                    console.error(error.stack);
                }
            }
        });
    });
}

function executeShellCommand(command) {
    return new Promise(function(resolve, reject) {
        Java.perform(function() {
            var Runtime = Java.use('java.lang.Runtime');
            var process = Runtime.getRuntime().exec(command);
            var bufferedReader = Java.use('java.io.BufferedReader');
            var InputStreamReader = Java.use('java.io.InputStreamReader');

            var reader = bufferedReader.$new(InputStreamReader.$new(process.getInputStream()));
            var line;
            var output = "";

            while ((line = reader.readLine()) !== null) {
                output += line + "\n";
            }
            reader.close();
            resolve(output);
        });
    });
}

var pkg_name;
var method_list;
executeShellCommand("cat /data/local/tmp/pkg_name.txt").then(function(output) {
    pkg_name = output.trim();
    executeShellCommand("cat /data/local/tmp/methods.json").then(function(output) {
        method_list = JSON.parse(output);
        hookSinkMethods(pkg_name, method_list);
    }).catch(function(error) {
        console.error("Error reading file: " + error);
        console.error(error.stack);
    });
}).catch(function(error) {
    console.error("Error reading file: " + error);
    console.error(error.stack);
});