import traceback

from loguru import logger
from .ExplorationAlgorithm import ExplorationAlgorithm
from ..utils.utils import Timer


class RandomAlgorithm(ExplorationAlgorithm):

    @staticmethod
    def explore(app, emulator, timesteps, timer, **kwargs):
        try:
            app.reset()
            t = Timer(timer)
            while not t.timer_expired():
                action = app.action_space.sample()
                o, _, done, _ = app.step(action)
                app.coverage_count += 1
                if (app.timesteps % 25) == 0 and app.instr:
                    app.instr_funct(udid=app.udid, package=app.package, coverage_dir=app.coverage_dir,
                                    coverage_count=app.coverage_count)
                if done:
                    app.reset()
            return True
        except Exception:
            logger.error(traceback.format_exc())
            return False
