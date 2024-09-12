from flask import Flask
import configparser
import os

app = Flask(__name__)
configs = configparser.ConfigParser()
configs.read(app.root_path + os.sep + "conf.ini")

from . import routes