from datetime import datetime


class Logger:
    def __init__(self, log_file='./logs/worker.log'):
        self.log_file = log_file

    def log(self, message):
        file = open(self.log_file, 'a')
        file.write('[' + datetime.today().strftime('%Y-%m-%d') + '] ' + message + "\n")
        file.close()
