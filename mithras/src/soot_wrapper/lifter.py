from loguru import logger
import os

from .errors import *

import jpype
import jpype.imports
from jpype.pickle import JPickler, JUnpickler
from jpype.types import *

from .sootir.soot_class import SootClass

self_dir = os.path.dirname(os.path.realpath(__file__))


class Lifter(object):

    def __init__(self, input_file=None, input_format="jar", ir_format="shimple", additional_jars=None,
                 additional_jar_roots=None, android_sdk=None, save_to_file=None):

        self.input_file = os.path.realpath(input_file)
        self.save_to_file = save_to_file
        allowed_irs = ["shimple", "jimple"]
        if ir_format not in allowed_irs:
            raise ParameterError("ir_format needs to be in " + repr(allowed_irs))
        self.ir_format = ir_format

        allowed_formats = ["jar", "apk"]
        if input_format not in allowed_formats:
            raise ParameterError("format needs to be in " + repr(allowed_formats))
        self.input_format = input_format

        self.jars_path = f"{os.path.abspath(os.path.dirname(__file__))}{os.sep}jars"

        if input_format == "jar":
            if android_sdk is not None:
                logger.warning("when input_format is 'jar', setting android_sdk is pointless")
            library_jars = ["rt.jar", "jce.jar"]
            absolute_library_jars = {os.path.realpath(os.path.join(self_dir, "../bin/" + jar)) for jar in library_jars}
            if additional_jars is not None:
                absolute_library_jars |= {os.path.realpath(jar) for jar in additional_jars}
            if additional_jar_roots is not None:
                for jar_root in additional_jar_roots:
                    for jar_name in os.listdir(jar_root):
                        if jar_name.endswith(".jar"):
                            absolute_path = os.path.realpath(os.path.join(jar_root, jar_name))
                            if absolute_path not in absolute_library_jars:
                                absolute_library_jars.add(absolute_path)
            bad_jars = [p for p in absolute_library_jars if ":" in p]
            if len(bad_jars) > 0:
                raise ParameterError("these jars have a semicolon in their name: " + repr(bad_jars))
            self.soot_classpath = ":".join(absolute_library_jars)

        elif input_format == "apk":
            if android_sdk is None:
                raise ParameterError("when format is apk, android_sdk should point to something like: "
                                     "~/Android/Sdk/platforms")
            if additional_jars is not None or additional_jar_roots is not None:
                logger.warning("when input_format is 'apk', setting additional_jars or additional_jar_roots is "
                               "pointless")
            self.android_sdk = android_sdk

        if save_to_file and os.path.exists(save_to_file):
            with open(save_to_file, "rb") as fd:
                if not jpype.isJVMStarted():
                    jpype.startJVM('-Xmx10g', convertStrings=True, classpath=[f'{self.jars_path}{os.sep}'
                                                                              f'soot-wrapper-1.0.jar',
                                                                              f'{self.jars_path}{os.sep}soot.jar'])

                junpickler = JUnpickler(fd)
                self.classes = junpickler.load()
        else:
            self._get_ir(save_to_file)

    def _get_ir(self, output_file):
        if not jpype.isJVMStarted():
            jpype.startJVM('-Xmx10g', convertStrings=True, classpath=[f'{self.jars_path}{os.sep}soot-wrapper-1.0.jar',
                                                                      f'{self.jars_path}{os.sep}soot.jar'])

        from wrapper.soot import SootWrapper

        logger.info("Analyzing app")
        wrapper = SootWrapper(self.input_file, self.android_sdk, self.ir_format)
        soot_chain = wrapper.getClasses()
        self.classes = {}
        if soot_chain is not None:
            logger.info("Converting classes")
            soot_chain_iterator = soot_chain.snapshotIterator()
            while soot_chain_iterator.hasNext():
                chain_class = soot_chain_iterator.next()
                if chain_class.isApplicationClass():
                    soot_class = SootClass.from_ir(chain_class)
                    self.classes[soot_class.name] = soot_class

        logger.info("Save classes")
        with open(output_file, "wb") as f:
            jpickler = JPickler(f)
            jpickler.dump(self.classes)
