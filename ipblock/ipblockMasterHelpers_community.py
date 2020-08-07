#!/usr/bin/python3

import config
import datetime
import time
import sys
import pymysql

def iAmMaster(action):
    if (action == 'request') or (action == 'release'):
        return True
