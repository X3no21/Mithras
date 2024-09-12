import sys
import os
import traceback

from jpype.pickle import JPickler, JUnpickler
from os.path import dirname, abspath
from androguard.core.bytecodes.apk import APK
from androguard.misc import AnalyzeAPK
from loguru import logger
import networkx as nx
import re

sys.path.append(dirname(dirname(abspath(__file__))))
from turi.project import Project
from soot_wrapper.lifter import Lifter
from frida_hooker.frida_hooker import FridaHooker, ApkExploded, ApkKilled, ApkStuck, FridaRunner


black_list_packages = ["java.",
                       "javax.",
                       "android.",
                       "com.android.",
                       "dalvik.",
                       "com.google.",
                       "com.facebook.",
                       "com.bumptech.",
                       "com.karumi.",
                       "com.kyleduo.",
                       "com.pierfrancescosoffritti.",
                       "cn.carbswang",
                       "info.hoang8f.",
                       "ui.",
                       "androidx.",
                       "sun.",
                       "org."]


def extract_graph(dex_files):
    call_graph = {}
    for dex in dex_files:
        for method in dex.get_methods():
            caller_converted = convert_dex_to_java(method_to_tuple(method))
            if is_method_insertable(caller_converted[0]):
                code = method.get_code()
                if code:
                    for ins in code.get_bc().get_instructions():
                        if ins.get_name().startswith('invoke-'):
                            idx = ins.get_ref_kind()
                            callee = dex.get_cm_method(idx)
                            if callee:
                                callee_converted = convert_dex_to_java(adjust_method_tuple(callee))
                                if is_method_insertable(callee_converted[0]):
                                    if caller_converted not in call_graph:
                                        call_graph[caller_converted] = []
                                    call_graph[caller_converted].append(callee_converted)
    return call_graph


def is_method_insertable(class_name):
    return not any([class_name.startswith(pack) for pack in black_list_packages])


def is_dex_method_insertable(class_name):
    return not any([class_name.startswith(f"L{pack.replace('.', '/')}") for pack in black_list_packages])


def adjust_method_tuple(method_tuple):
    params = tuple(method_tuple[2][0][1:-1].split(" ")) if method_tuple[2][0] != "()" else tuple()
    return (method_tuple[0], method_tuple[1], params, method_tuple[2][1])


def method_to_tuple(method):
    class_name = method.class_name
    method_name = method.name

    descriptor = method.get_descriptor()
    params = descriptor.split(')')[0][1:]
    if params != "":
        params = params.split(' ')
    ret_type = descriptor.split(')')[-1]
    if ret_type == '':
        ret_type = 'void'

    return (class_name, method_name, params, ret_type)


def get_android_components_methods(dvm, components):
    component_methods = {}
    for comp_class in components:
        match = re.search(r"L(.*/?)*;", comp_class)
        if not match:
            comp_class_name = f"L{comp_class.replace('.', '/')};"
        else:
            comp_class_name = comp_class
        component_methods[comp_class] = list()

        for dex in dvm:
            for method in dex.get_methods():
                if method.get_class_name() == comp_class_name:
                    method_tuple = method_to_tuple(method)
                    if method_tuple not in component_methods[comp_class]:
                        component_methods[comp_class].append(method_tuple)

    return component_methods


def find_fragment_classes(dex_files):
    fragment_classes = []
    potential_fragments = ['Landroid/app/Fragment;', 'Landroidx/fragment/app/n;']

    for dex in dex_files:
        for cls in dex.get_classes():
            if is_dex_method_insertable(cls.get_name()):
                super_class = cls.get_superclassname()
                if super_class in potential_fragments:
                    fragment_classes.append(cls.get_name())
                else:
                    while super_class != 'Ljava/lang/Object;':
                        if super_class in potential_fragments:
                            fragment_classes.append(cls.get_name())
                            break
                        current_class = dex.get_class(super_class)
                        if current_class is None:
                            break
                        super_class = current_class.get_superclassname()

    return fragment_classes


def java_type_to_dex_type(java_type):
    mapping = {
        'void': 'V',
        'boolean': 'Z',
        'byte': 'B',
        'char': 'C',
        'short': 'S',
        'int': 'I',
        'long': 'J',
        'float': 'F',
        'double': 'D'
    }

    if java_type.endswith('[]'):
        return '[' + java_type_to_dex_type(java_type[:-2])

    if java_type in mapping:
        return mapping[java_type]

    if '.' in java_type:
        return f'L{java_type.replace(".", "/")};'

    return java_type

def dex_type_to_java_type(dex_type):
    reverse_mapping = {
        'V': 'void',
        'Z': 'boolean',
        'B': 'byte',
        'C': 'char',
        'S': 'short',
        'I': 'int',
        'J': 'long',
        'F': 'float',
        'D': 'double'
    }

    array_prefix_count = 0
    while dex_type.startswith('['):
        array_prefix_count += 1
        dex_type = dex_type[1:]

    base_type = reverse_mapping.get(dex_type, None)
    if base_type is not None:
        return base_type + '[]' * array_prefix_count

    if dex_type.startswith('L') and dex_type.endswith(';'):
        java_type = dex_type[1:-1].replace('/', '.')
        return java_type + '[]' * array_prefix_count

    return dex_type


def convert_java_to_dex(input_list):
    converted_list = []
    for i in range(len(input_list)):
        if isinstance(input_list[i], list) or isinstance(input_list[i], tuple):
            converted_list.append([java_type_to_dex_type(e) for e in input_list[i]])
        else:
            if i == 1:
                if input_list[i] == '$init':
                    converted_list.append('<init>')
                    continue
                elif input_list[i] == '$clinit':
                    converted_list.append('<clinit>')
                    continue
            converted_list.append(java_type_to_dex_type(input_list[i]))
    converted_list[2] = tuple(converted_list[2])
    return tuple(converted_list)


def convert_dex_to_java(input_list):
    converted_list = []
    for i in range(len(input_list)):
        if isinstance(input_list[i], list) or isinstance(input_list[i], tuple):
            converted_list.append([dex_type_to_java_type(e) for e in input_list[i]])
        else:
            if i == 1:
                if input_list[i] == '<init>':
                    converted_list.append('$init')
                    continue
                elif input_list[i] == '<clinit>':
                    converted_list.append('clinit')
                    continue
            converted_list.append(dex_type_to_java_type(input_list[i]))
    converted_list[2] = tuple(converted_list[2])
    return tuple(converted_list)


class SinkCfg:
    def __init__(self, cg, sinks, paths_to_sinks, senders, sweet_spots, intermediate_methods_to_hook, sink_methods_to_hook,
                 automated_senders, sink_activities, sink_services, sink_broadcast, listeners, fragments):
        self.cg = cg
        self.sinks = sinks
        self.paths_to_sinks = paths_to_sinks
        self.intermediate_methods_to_hook = intermediate_methods_to_hook
        self.sink_methods_to_hook = sink_methods_to_hook
        self.senders = senders
        self.sweet_spots = sweet_spots
        self.automated_senders = automated_senders
        self.sink_activities = sink_activities
        self.sink_services = sink_services
        self.sink_broadcast = sink_broadcast
        self.listeners = listeners
        self.fragments = fragments


class TargetMethodsHooker(object):

    def __init__(self, config, ares_config, reinstall_app, hooker, lifter):
        self.senders = None
        self.sink_broadcast = None
        self.sink_services = None
        self.sink_activities = None
        self.listeners = None
        self.fragments = None
        self.sink_methods_to_hook = None
        self.intermediate_methods_to_hook = None
        self.receivers = None
        self.services = None
        self.activities = None
        self.paths_to_targets = None
        self.soot_sink_methods = None
        self.config = config
        self.hooker = hooker if hooker else FridaHooker(config, ares_config, reinstall_app)
        self.lifter = lifter
        self.cg = None


    def start(self, apk_path=None, cfg_path=None, senders=None, sweet_spots=None, automated_senders=None,
              hook_only_targets=True, lifter=None):

        try:
            if cfg_path is not None and os.path.exists(cfg_path):
                with open(cfg_path, "rb") as fd:
                    unpickler = JUnpickler(fd)
                    sink_cfg = unpickler.load()

                    self.cg = sink_cfg.cg
                    self.soot_sink_methods = sink_cfg.sinks
                    self.paths_to_targets = sink_cfg.paths_to_sinks
                    self.intermediate_methods_to_hook = sink_cfg.intermediate_methods_to_hook
                    self.sink_methods_to_hook = sink_cfg.sink_methods_to_hook
                    self.sink_activities = sink_cfg.sink_activities
                    self.sink_services = sink_cfg.sink_services
                    self.sink_broadcast = sink_cfg.sink_broadcast
                    self.listeners = sink_cfg.listeners
                    self.fragments = sink_cfg.fragments

                    self.senders = sink_cfg.senders

                    # senders.clear()
                    # senders.extend(sink_cfg.senders)

                    # sweet_spots.clear()
                    # sweet_spots.extend(sink_cfg.sweet_spots)

                    # automated_senders.clear()
                    # automated_senders.extend(sink_cfg.automated_senders)

                    return

            sink_methods = []
            sink_methods.extend((senders[i], "senders") for i in range(len(senders)))
            sink_methods.extend((sweet_spots[i], "sp") for i in range(len(sweet_spots)))
            sink_methods.extend((automated_senders[i], "automated") for i in range(len(automated_senders)))

            if hook_only_targets:
                self.hooker.start([sink[0] for sink in sink_methods], force_hook=True, get_instances=True)
            else:
                self.lifter = lifter
                if not self.lifter:
                    f = os.path.abspath(
                        os.path.dirname(os.path.dirname(os.path.dirname(__file__)))) + os.sep + "pickle_apk_soot" + os.sep \
                        + self.config['proc_name']

                    self.lifter = Lifter(self.config['smartphone_apk_path'], input_format="apk",
                                         android_sdk=self.config['android_sdk_platforms'], save_to_file=f)

                logger.debug("Start Computing CFG")
                app_turi = Project(app_path=self.config['smartphone_apk_path'], lifter=self.lifter)
                logger.debug("End Computing CFG")
                apk = APK(self.config['smartphone_apk_path'])
                self.activities = apk.get_activities()
                self.services = apk.get_services()
                self.receivers = apk.get_receivers()
                self.sink_activities = set()
                self.sink_services = set()
                self.sink_broadcast = set()
                if not self.cg:
                    self.cg = app_turi.callgraph().graph

                # get soot method sinks
                self.soot_sink_methods = dict()
                for node in self.cg.nodes():
                    for sink in sink_methods:
                        if sink[0][0] == node.class_name and sink[0][1] == node.name and len(sink[0][2]) == len(node.params) \
                                and node.ret == sink[0][3]:
                            param_ind = 0
                            while param_ind < len(sink[0][2]):
                                if sink[0][2][param_ind] != node.params[param_ind]:
                                    break
                                param_ind += 1

                            if param_ind == len(sink[0][2]):
                                sink[0][2] = tuple(sink[0][2])
                                self.soot_sink_methods[tuple(sink[0])] = node
                                break

                # for each sink, extraction of all the shortest paths from a layout function
                self.paths_to_targets = {sink: [] for sink in self.soot_sink_methods.values()}

                apk, dvm, analysis = AnalyzeAPK(apk_path)
                call_graph = extract_graph(dvm)
                fragments = get_android_components_methods(dvm, find_fragment_classes(dvm))
                activities = get_android_components_methods(dvm, apk.get_activities())
                services = get_android_components_methods(dvm, apk.get_services())
                receivers = get_android_components_methods(dvm, apk.get_receivers())
                self.listeners = set()
                self.fragments = set()

                graph = nx.Graph()
                for caller in call_graph:
                    for callee in call_graph[caller]:
                        graph.add_edge(caller, callee)

                for target_method in self.soot_sink_methods:
                    for comp_class, methods in fragments.items():
                        paths = []
                        for method in methods:
                            method_converted = convert_dex_to_java(method)
                            try:
                                paths.append(
                                    nx.shortest_path(graph, source=method_converted, target=target_method))
                            except:
                                continue

                            self.fragments.add(method_converted)

                        if len(paths) > 0:
                            self.sink_activities.add(comp_class)
                            self.paths_to_targets[self.soot_sink_methods[target_method]].extend(paths)

                    for comp_class, methods in activities.items():
                        paths = []
                        for method in methods:
                            method_converted = convert_dex_to_java(method)
                            try:
                                paths.append(
                                    nx.shortest_path(graph, source=method_converted, target=target_method))
                            except:
                                continue

                        if len(paths) > 0:
                            self.sink_activities.add(comp_class)
                            self.paths_to_targets[self.soot_sink_methods[target_method]].extend(paths)

                    for comp_class, methods in services.items():
                        paths = []
                        for method in methods:
                            method_converted = convert_dex_to_java(method)
                            try:
                                paths.append(
                                    nx.shortest_path(graph, source=method_converted, target=target_method))
                            except:
                                continue

                        if len(paths) > 0:
                            self.sink_services.add(comp_class)
                            self.paths_to_targets[self.soot_sink_methods[target_method]].extend(paths)

                    for comp_class, methods in receivers.items():
                        paths = []
                        for method in methods:
                            method_converted = convert_dex_to_java(method)
                            try:
                                paths.append(
                                    nx.shortest_path(graph, source=method_converted, target=target_method))
                            except:
                                continue

                        if len(paths) > 0:
                            self.sink_broadcast.add(comp_class)
                            self.paths_to_targets[self.soot_sink_methods[target_method]].extend(paths)

                self.intermediate_methods_to_hook = set()
                for paths in self.paths_to_targets.values():
                    for path in paths:
                        for node in path:
                            self.intermediate_methods_to_hook.add(node)

                self.sink_methods_to_hook = set()
                for sink in sink_methods:
                    self.sink_methods_to_hook.add((sink[0][0], sink[0][1], tuple(sink[0][2]), sink[0][3]))

                self.intermediate_methods_to_hook.difference_update(self.sink_methods_to_hook)

                """
                if cfg_path is not None:
                    os.makedirs(os.path.abspath(os.path.dirname(cfg_path)), exist_ok=True)
                    with open(cfg_path, "wb+") as fd:
                        pickler = JPickler(fd)
                        sink_cfg = SinkCfg(self.cg, self.soot_sink_methods, self.paths_to_targets, senders, sweet_spots,
                                           self.intermediate_methods_to_hook, self.sink_methods_to_hook, automated_senders,
                                           self.sink_activities, self.sink_services, self.sink_broadcast, self.listeners,
                                           self.fragments)
                        logger.debug("Pickling CFG")
                        pickler.dump(sink_cfg)
                        logger.debug("Pickled CFG")
                """
        except Exception as e:
            logger.error(e)
            logger.error(traceback.format_exc())
