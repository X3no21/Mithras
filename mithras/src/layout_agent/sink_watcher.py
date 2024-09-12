from loguru import logger
import threading
import time


class SinkWatcher:
    def __init__(self, lock: threading.Lock, methods_called: list, sink_reached_event: threading.Event):
        self.watcher = None
        self.stop = False
        self.lock = lock
        self.methods_called = methods_called
        self.sink_reached_event = sink_reached_event

    def run(self):
        while True:
            self.lock.acquire()
            try:
                if self.stop:
                    break
                for method in self.methods_called:
                    if "SINK" in method:
                        logger.debug("SINK Found")
                        self.stop = True
                        self.sink_reached_event.set()
                        break
            except Exception as e:
                logger.error(e)
            finally:
                self.lock.release()
            time.sleep(0.5)

    def start_watcher(self):
        self.watcher = threading.Thread(target=self.run)
        self.watcher.start()

    def stop_watcher(self):
        self.lock.acquire()
        try:
            self.stop = True
        finally:
            self.lock.release()
