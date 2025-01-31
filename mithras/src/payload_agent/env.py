import random
import re
import threading
import time

import requests

from gym import Env
from gym import spaces
import numpy as np
import json
import os


class PayloadEnv(Env):

    def __init__(self, app_env, log_dir: str, firmware_name: str, firmware_mapping: dict,
                 iot_device_execution_trace_path: str, max_num_sink_parameters: int, prefixes_path: str,
                 suffixes_path: str, encoders_path: str, rce_to_file_path: str, package: str,
                 working_dir: str, episode: int, max_timesteps: int, php_files: str, reward_sink_reached: float,
                 reward_good_intermediate: float, reward_bad_intermediate: float, reward_exploit_done: float,
                 reward_exploit_not_done: float, rce_call_log: str,
                 iot_device_execution_trace_file_lock: threading.Lock,
                 exec_output_file_lock: threading.Lock, coverage_guiding=False):
        self.max_num_sink_parameters = max_num_sink_parameters

        self.package = package
        self.coverage_guiding = coverage_guiding
        self.working_dir = working_dir
        self.log_dir = log_dir
        self.firmware_name = firmware_name
        self.firmware_mapping = firmware_mapping
        self.rce_call_log = rce_call_log
        self.app_env = app_env
        self.iot_device_execution_trace_path = iot_device_execution_trace_path
        self.reward_sink_reached = reward_sink_reached
        self.reward_exploit_done = reward_exploit_done
        self.reward_exploit_not_done = reward_exploit_not_done
        self.reward_good_intermediate = reward_good_intermediate
        self.reward_bad_intermediate = reward_bad_intermediate
        self.reward_history = []
        self.php_files = php_files
        self.iot_device_execution_trace_file_lock = iot_device_execution_trace_file_lock
        self.exec_output_file_lock = exec_output_file_lock
        self.layout_sink_method_called_signature = ""
        self.seeds_with_coverage = dict()

        with open(prefixes_path, "r") as f:
            self.prefixes = f.readlines()

        with open(suffixes_path, "r") as f:
            self.suffixes = f.readlines()
            self.suffixes = [suff.strip() for suff in self.suffixes]

        with open(encoders_path, "r") as f:
            self.encoders = f.readlines()
            self.encoders = [enc.strip() for enc in self.encoders]

        with open(rce_to_file_path, "r") as f:
            self.rce_to_file = f.readlines()
            self.rce_to_file = [rce.strip() for rce in self.rce_to_file]

        self.num_operators = max(len(self.prefixes), len(self.suffixes), len(self.rce_to_file)) - 1
        self.operations = ["add_prefix", "add_suffix", "rce_to_file"]
        self.additional_operators = ["nothing", "reset_seed", "encode_chars"]

        # action vector: [field_to_modify, operator_idx, mutation, additional]
        self.action_space: spaces.Box = spaces.Box(low=np.array([0, 0, 0, 0]),
                                                   high=np.array(
                                                       [self.max_num_sink_parameters, len(self.operations) - 1,
                                                        self.num_operators, len(self.additional_operators) - 1]),
                                                   dtype=np.int64)

        self.php_files_dict = dict()
        with open(self.php_files, "r") as f:
            for php_file in f:
                self.php_files_dict[php_file.strip().split("image_fs")[1]] = 0

        self.observation_space = spaces.Box(low=0, high=1, shape=[(len(self.php_files_dict.keys()))], dtype=np.int32)
        self.observation = list(self.php_files_dict.values())
        self.timesteps = 0
        self.episode = episode
        self.max_timesteps = max_timesteps

        self.app_env = app_env
        self.seed_for_method = dict()
        self.num_if_traversed_for_sink = dict()
        self.parameters_to_modify = dict()

    def get_action_space(self):
        return list(self.action_space.high)

    def get_observation(self):
        self.iot_device_execution_trace_file_lock.acquire()
        try:
            iot_execution_trace = []
            with open(self.iot_device_execution_trace_path, "r") as f:
                for line in f:
                    if "SCRIPT" in line:
                        match = re.search(r"<FILE>(.*)</FILE>", line.strip().split("SCRIPT")[1])
                        if match:
                            iot_execution_trace.append(match.group(1).split("image_fs")[1])
                    elif "COMPLETE" in line:
                        match = re.search(r"<FILE>(.*)</FILE>", line.strip().split("COMPLETE")[1])
                        if match:
                            iot_execution_trace.append(match.group(1).split("image_fs")[1])
                    elif "INTERMEDIATE" in line:
                        match = re.search(r"<FILE>(.*)</FILE>", line.strip().split("INTERMEDIATE")[1])
                        if match:
                            iot_execution_trace.append(match.group(1).split("image_fs")[1])
                    elif "SINK" in line:
                        match = re.search(r"<FILE>(.*)</FILE>", line.strip().split("SINK")[1])
                        if match:
                            iot_execution_trace.append(match.group(1).split("image_fs")[1])

            tmp_php_files_traversed = self.php_files_dict.copy()
            for php_file in iot_execution_trace:
                tmp_php_files_traversed[php_file] = 1
            self.observation = tmp_php_files_traversed
        finally:
            self.iot_device_execution_trace_file_lock.release()

    def step(self, action_number):
        try:
            action_number = action_number.astype(int)
            if action_number[0] >= self.get_action_space()[0]:
                done = self._termination()
                with open(self.log_dir + os.sep + "action_logs.txt", "a+") as f:
                    f.write(f"<EPISODE>{self.episode}</EPISODE><STEP>{self.timesteps}</STEP>"
                            f"<ACT>Not Valid Action</ACT><INPUT></INPUT><ADD>Non Valid Additional</ADD>"
                            f"<REW>{-150.0}</REW><DONE>{done}</DONE><EXPLOIT>False<EXPLOIT>"
                            f"<INFO>{json.dumps({})}</INFO>\n")
                return self.observation, -150.0, np.array(done), {}

            self.timesteps += 1
            action_str, observation, reward, exploit, done, info = self.step2(action_number)
            with open(self.log_dir + os.sep + "action_logs.txt", "a+") as f:
                f.write(f"<EPISODE>{self.episode}</EPISODE><STEP>{self.timesteps}</STEP>"
                        f"<ACT>{self.operations[action_number[1]]}</ACT>"
                        f"<ADD>{self.additional_operators[action_number[3]]}</ADD><INPUT>{action_str}</INPUT>"
                        f"<REW>{reward}</REW><DONE>{done}</DONE><EXPLOIT>{exploit}<EXPLOIT>"
                        f"<INFO>{json.dumps(info)}</INFO>\n")

            return observation, reward, done, info
        finally:
            self.parameters_to_modify = dict()
            self.iot_device_execution_trace_file_lock.acquire()
            try:
                if not os.path.exists(self.log_dir + os.sep + "log.txt"):
                    with open(self.log_dir + os.sep + "log.txt", "w+"):
                        pass

                with open(self.log_dir + os.sep + "log.txt", "a") as f:
                    with open(self.iot_device_execution_trace_path, "r") as f1:
                        for line in f1:
                            f.write(f"<EPISODE>{self.episode}</EPISODE><STEP>{self.timesteps}</STEP>{line}\n")

                with open(self.iot_device_execution_trace_path, "w+"):
                    pass
            finally:
                self.iot_device_execution_trace_file_lock.release()

            self.exec_output_file_lock.acquire()
            try:
                with open(self.rce_call_log, "w+"):
                    pass
            finally:
                self.exec_output_file_lock.release()

    def step2(self, action_number):
        action_str = ""
        dict_to_return = dict()
        method_signature, class_name, method_parameter_values = self.get_method_parameter_values()

        if self.coverage_guiding and len(self.seeds_with_coverage) > 0:
            epsilon =  random.randint(0, 100)
            if epsilon <= 60:
                self.seed_for_method[method_signature] = max(self.seeds_with_coverage.items(), key=lambda x: x[1])[0]

        if self.additional_operators[action_number[3]] == "reset_seed":
            self.seed_for_method[method_signature] = method_parameter_values

        if self.operations[action_number[1]] == "add_prefix":
            if action_number[2] >= len(self.prefixes):
                action_number[2] %= len(self.prefixes)

            new_param_value = self.prefixes[action_number[2]] + self.seed_for_method[method_signature]
            dict_to_return["field_name"] = list(method_parameter_values.keys())[action_number[0]]
            dict_to_return["field_value"] = new_param_value
            action_str = dict_to_return["field_value"]

        if self.operations[action_number[1]] == "add_suffix":
            if action_number[2] >= len(self.suffixes):
                action_number[2] %= len(self.suffixes)

            if method_signature not in self.seed_for_method:
                self.seed_for_method[method_signature] = method_parameter_values

            dict_to_return["field_name"] = list(method_parameter_values.keys())[action_number[0]]
            new_param_value = (self.seed_for_method[method_signature][dict_to_return["field_name"]]
                               + self.prefixes[action_number[2]])

            dict_to_return["field_value"] = new_param_value
            action_str = dict_to_return["field_value"]

        if self.operations[action_number[1]] == "rce_to_file":
            if action_number[2] >= len(self.rce_to_file):
                action_number[2] %= len(self.rce_to_file)

            dict_to_return["field_name"] = list(method_parameter_values.keys())[action_number[0]]
            new_param_value = self.rce_to_file[action_number[2]].replace("rce",
                                                                         f"rce{self.app_env.rce_file_count}")
            self.app_env.rce_file_count += 1

            dict_to_return["field_value"] = new_param_value
            action_str = dict_to_return["field_value"]

        if self.additional_operators[action_number[3]] == "encode_chars":
            action_number[2] %= len(self.encoders)

            if method_signature not in self.seed_for_method:
                self.seed_for_method[method_signature] = method_parameter_values

            replacement = self.encoders[action_number[2]]
            replacement_key, replacement_value = replacement.split(" = ")
            new_param_value = dict_to_return["field_value"].replace(replacement_key, replacement_value)

            dict_to_return["field_value"] = new_param_value
            action_str = dict_to_return["field_value"]

        self.app_env.script.post(dict_to_return)
        time.sleep(10)
        self.get_observation()
        reward, exploit = self.compute_reward(class_name, self.operations[action_number[1]] == "rce_to_file")
        done = self._termination()
        return action_str, self.observation, reward, exploit, done, {}

    def compute_reward(self, class_name: str, is_rce_to_file: bool) -> (float, bool):
        sink_methods_reached = self.get_method_reached_type("EXEC")
        if len(sink_methods_reached) > 0:
            if is_rce_to_file:
                r = requests.get(f"http://{self.firmware_mapping[self.firmware_name]['ip_address']}/HNAP1/rce")
                if re.search("uid=\d+\s?\([a-zA-Z0-9]+\) gid=\d+\s?\([a-zA-Z0-9]+\)", r.text):
                    self.reward_history.append(self.reward_exploit_done)
                    return self.reward_exploit_done, True
            else:
                self.exec_output_file_lock.acquire()
                try:
                    with open(self.rce_call_log, "r") as f:
                        exec_logs = f.read()
                finally:
                    self.exec_output_file_lock.release()

                for output in exec_logs.split("OUTPUT: "):
                    # id command executed
                    if re.search("uid=\d+\s?\([a-zA-Z0-9]+\) gid=\d+\s?\([a-zA-Z0-9]+\)", output):
                        self.reward_history.append(self.reward_exploit_done)
                        return self.reward_exploit_done, True

                    """
                    # whoami command
                    if output.strip() == self.iot_device_user:
                        return self.reward_exploit_done, True
    
                    # pwd
                    if re.match("^(\/[\w-]+)+(.[a-zA-Z]+?)$", output):
                        return self.reward_exploit_done, True
    
                    # passwd
                    if re.search("\w{1,32}:x:\d+:\d+:\w*:(\/[\w-]+)+(.[a-zA-Z]+?):(\/[\w-]+)+(.[a-zA-Z]+?)", output):
                        return self.reward_exploit_done, True
    
                    # shadow
                    if re.search("\w{1,32}:(\$1\$|\$2a\$|\$2y\$|\$5\$|\$6\$|\$y\$)"
                                 "[a-zA-Z0-9!@#%^&*()_+\-=\[\]{}|;\':\",./<>?~`]{15,20}:\d+:\d+:\d+:\d*:\d*:\d*", output):
                        return self.reward_exploit_done, True
    
                    # nc reverse shell
                    for i in range(4):
                        p = subprocess.Popen(["sshpass", "-p", self.iot_password, "ssh", "-P", self.iot_ssh_port,
                                              f"{self.iot_device_user}@{self.iot_device_address}", "lsof", "-t",
                                              f"-i:{1234 + i}"], stdout=subprocess.PIPE)
                        out, _ = p.communicate()
                        out = out.decode()
                        if re.search("^\d+$", out):
                            return self.reward_exploit_done
                    """
            reward = self.reward_sink_reached + self.reward_exploit_not_done
            self.reward_history.append(reward)
            return reward, False

        if_reached = self.get_method_reached_type("IF")
        num_if_reached = len(if_reached)
        if not self.num_if_traversed_for_sink[class_name]:
            self.num_if_traversed_for_sink[class_name] = []
        self.num_if_traversed_for_sink[class_name].append(num_if_reached)

        if len(self.num_if_traversed_for_sink[class_name]) >= 2:
            if self.num_if_traversed_for_sink[class_name][-1] >= self.num_if_traversed_for_sink[class_name][2]:
                self.reward_history.append(self.reward_good_intermediate + self.reward_exploit_not_done)
                return self.reward_good_intermediate + self.reward_exploit_not_done
            else:
                self.reward_history.append(self.reward_bad_intermediate + self.reward_exploit_not_done)
                return self.reward_bad_intermediate + self.reward_exploit_not_done
        else:
            self.reward_history.append(self.reward_good_intermediate + self.reward_exploit_not_done)
            return self.reward_good_intermediate + self.reward_exploit_not_done

    def reset(self):
        self.timesteps = 0
        self.parameters_to_modify = dict()

    def render(self):
        endpoints_triggered = self.get_method_reached_type("SINK")
        if len(endpoints_triggered) > 0:
            return endpoints_triggered[0]
        return "No endpoint"

    def _termination(self) -> bool:
        if self.timesteps >= self.max_timesteps:
            return True
        else:
            return False

    def get_method_parameter_values(self) -> tuple[str, str, dict]:
        class_name = self.parameters_to_modify.pop("className")
        return self.layout_sink_method_called_signature, class_name, self.parameters_to_modify

    def get_method_reached_type(self, method_type) -> list[str]:
        self.iot_device_execution_trace_file_lock.acquire()
        try:
            methods_reached = []
            with open(self.iot_device_execution_trace_path, "r") as f:
                for line in f:
                    if method_type in line:
                        methods_reached.append(line)

            return methods_reached
        finally:
            self.iot_device_execution_trace_file_lock.release()
