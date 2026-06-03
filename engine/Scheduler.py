
import logging
import threading
import time

from tasks.PullSSLCerts import PullNewSSLCertificatesTask
import schedule
import utils

class Scheduler:
    def __init__(self, app):
        self.app = app
        self.logger = logging.getLogger("Scheduler")
        
    def _run_pull_new_ssl_certificates(self):    
        try:
            task = PullNewSSLCertificatesTask()
            task.run()
        except Exception as e:
            self.logger.error(f"Error running PullNewSSLCertificatesTask: {e}")
            
    def start(self):
        schedule.every(24).hours.do(self._run_pull_new_ssl_certificates)  # Run SSL certificate task every 24 hours
            
        self.run_continuously()
        
    def stop(self):
        if hasattr(self, 'cease_continuous_run'):
            self.cease_continuous_run.set()
            self.logger.info("Scheduler stopped")        
    

    def run_continuously(self, interval=1):
        self.cease_continuous_run = threading.Event()
        parent = self

        class ScheduleThread(threading.Thread):
            def run(self):
                while not parent.cease_continuous_run.is_set():
                    schedule.run_pending()
                    time.sleep(interval)

        self.continuous_thread = ScheduleThread()
        self.continuous_thread.start()
        return self.cease_continuous_run