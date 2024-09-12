import abc


class ExplorationAlgorithm:
    __metaclass__ = abc.ABCMeta

    @staticmethod
    @abc.abstractmethod
    def explore(app, emulator, timesteps, timer, **kwargs):
        raise NotImplementedError()
