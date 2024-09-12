from .arg_values.random_values import RandomValues
from .arg_values.formatted_values import FormattedValues
#from rl.rl import RL


class Values:
    def __init__(self, config, generator=None):
        self.config = config
        self.gen_vals = []
        if generator is not None:
            try:
                gen = eval(generator)(self.config)
                self.gen_vals = [gen]
            except:
                pass

        if not self.gen_vals:
            self.gen_vals = [RandomValues(), FormattedValues(config)]

        self.index = 0

        #self.rl = RL(num_iters=0)
        #self.rl.train_model()

    def get_name_fuzz_function(self, vtype):
        if vtype.startswith('[B'):
            return 'fuzz_byte_array'
        elif vtype.startswith('[I'):
            return 'fuzz_int_array'
        else:
            return 'fuzz_' + vtype.replace('.', '_').replace('[]', '_array')

    def create_value(self, obj_type, action, frida_obj_creator, *kargs, **kwargs):
        f_name = self.get_name_fuzz_function(obj_type)
        old_index = self.index

        while True:
            if hasattr(self.gen_vals[self.index], f_name):
                # place step function
                # to_ret = getattr(self.gen_vals[self.index], f_name)(frida_obj_creator, *kargs, **kwargs)
                if action is not None:
                    self.index = (self.index + 1) % len(self.gen_vals)
                    return action

            self.index = (self.index + 1) % len(self.gen_vals)
            if old_index == self.index:
                return None

    def str_to_byte(self, b):
        return int(b)

    def str_to_int(self, i):
        return int(i)

    def str_to_String(self, s):
        return s

    def str_to_float(self, f):
        return float(f)

    def str_to_boolean(self, b):
        return bool(b)

    def str_to_Integer(self, i):
        return int(i)

    def str_to_Float(self, f):
        return float(f)

    def str_to_Doable(self, f):
        return float(f)

    def str_to_java_lang_String(self, s):
        return s

