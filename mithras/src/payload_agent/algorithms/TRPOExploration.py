import os
import traceback

from sb3_contrib import TRPO
from loguru import logger
from .ExplorationAlgorithm import ExplorationAlgorithm
from ..utils.TimerCallback import TimerCallback
from ..utils.wrapper import TimeFeatureWrapper


class TRPOAlgorithm(ExplorationAlgorithm):

    @staticmethod
    def explore(app, emulator, appium, timesteps, timer, save_policy=False, app_name='', reload_policy=False,
                policy_dir='.', cycle=0, train_freq=5, target_update_interval=10, **kwargs):
        try:
            app.reset()
            env = TimeFeatureWrapper(app)
            # Loading a previous policy and checking file existence
            if reload_policy and (os.path.isfile(f'{policy_dir}{os.sep}{app_name}.zip')):
                temp_dim = env.action_space.high[0]
                env.action_space.high[0] = env.env.ACTION_SPACE
                print(f'Reloading Policy {app_name}.zip')
                model = TRPO.load(f'{policy_dir}{os.sep}{app_name}', env)
                env.action_space.high[0] = temp_dim
            else:
                logger.info('Starting training from zero')
                model = TRPO("MlpPolicy", env, verbose=1)
            model.env.envs[0].check_activity()
            callback = TimerCallback(timer=timer, app=app)
            model.learn(total_timesteps=timesteps, callback=callback)
            # It will overwrite the previous policy
            if save_policy:
                print('Saving Policy...')
                model.action_space.high[0] = model.env.envs[0].ACTION_SPACE
                model.save(f'{policy_dir}{os.sep}{app_name}')
            return True
        except Exception as e:
            logger.error(traceback.format_exc())
            return False
