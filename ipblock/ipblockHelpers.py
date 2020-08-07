#!/usr/bin/python3

import config
import datetime
import time
import argparse
import yaml
import os.path
import sys
import pymysql
import subprocess



#######################################################
#
#   Various Functions
#
#######################################################
def parseArgs():
    try:
      parser = argparse.ArgumentParser(description='ipblock')

      parser.add_argument('-v', '--verbose', dest='isVerbose', action='store_true', help='Enable Verbose mode')
      parser.add_argument('-l', '--loglevel', dest='logLevel', help='Set loglevel (0-9)', default=-1, type=int)
      parser.add_argument('-c', '--config', dest='configFile', help='Configuration file', required=True)
      config.args = parser.parse_args()

      if config.args.isVerbose:
          config.isVerbose = True
      else:
          config.isVerbose = False
    except:
        print("Error, Argument Parser: %s" % sys.exc_info()[1])
        return False

    return True


def writeLog(level, logMessage):
    strNow = datetime.datetime.now().isoformat()
    prefixMessage = "%s: svc=%s env=%s" % (strNow, config.svc, config.env)

    #  If Verbose, write everything to stdout
    if config.isVerbose == True:
        print("%s %s" % (prefixMessage, logMessage))

    if level <= config.logLevel:
        config.activitylogFileFH.write("%s %s\n" % (prefixMessage, logMessage))

    return


def readConfigData():
    if os.path.exists(config.args.configFile):
        fromConfigFile = yaml.safe_load(open(config.args.configFile))
        try:
            config.ConfigData.update(fromConfigFile)
        except:
            print("Error: error reading configuration file. %s" % sys.exc_info()[1])
            return False
    else:
        print("Error: %s does not exist" % config.args.configFile)
        False

    return True


def createDBconnection(mysqlhost, mysqlport, mysqluser, mysqlpass, mysqldb, mysqltimeout):
    ssl = {'cipher': 'HIGH:!DH:!aNULL', 'tls-versions': 'tls1.1'}
    #ssl = {'cipher': 'ANY'}
    config.mydb = pymysql.connect(host=mysqlhost,
        user=mysqluser,
        passwd=mysqlpass,
        port=mysqlport,
        db=mysqldb,
        connect_timeout=mysqltimeout,
        use_unicode=True,
        charset="utf8",
        ssl=ssl
        )
    try:
        config.cursor = config.mydb.cursor()
    except:
        print("Error: Unable to connect to DB. %s" % sys.exc_info()[1])
        return False

    if (int(config.logLevel) > 7) or (config.isVerbose):
        print("MySQL Server version ", config.mydb.get_server_info())
        config.cursor.execute("select database();")
        record = config.cursor.fetchall()
        print("Database: %s" % record)
        config.cursor.execute("SHOW STATUS LIKE 'Ssl_cipher'")
        print("SSL: %s" % str(config.cursor.fetchone()))

    return True


def addToSuspect(ip, port=0):
    mystatement = "INSERT INTO " + config.tableNameSuspect + " (DateTime, IP, svc, pot) VALUES (%s, %s, %s, %s)"
    if port != 0:
        values = (datetime.datetime.now(), ip, config.svc + "-" + str(port), config.pot)
    else:
        values = (datetime.datetime.now(), ip, config.svc, config.pot)

    count = 0
    while count < config.retryCount:
        try:
            config.cursor.execute(mystatement, values)
            config.mydb.commit()
            count = config.retryCount + 1
        except:
            writeLog(1, "action=\"db Reconnect\" retry=%d" % count )
            try:
                config.mydb.ping(True)
                config.cursor.execute(mystatement, values)
                config.mydb.commit()
                count = config.retryCount + 1
            except:
                count += 1
                time.sleep(count)

    if count == config.retryCount:
        if port != 0:
            writeLog(1, "svc=%s-%d action=\"failedlogin to suspect\" msg=\"error: unable to access db\" suspect=%s" % (config.svc, port, ip))
        else:
            writeLog(1, "svc=%s action=\"failedlogin to suspect\" msg=\"error: unable to access db\" suspect=%s" % (config.svc, ip))
        # todo - Enhancement.  Save for later instead of skipping when DB is down/unavailable.
    else:
        if port != 0:
            writeLog(5, "svc=%s-%d action=\"failedlogin to suspect\" suspect=%s" % (config.svc, port, ip))
        else:
            writeLog(5, "svc=%s action=\"failedlogin to suspect\" suspect=%s" % (config.svc, ip))


def getAllIps(tableName, sorted=False):
    try:
        config.mydb.ping(True)
        mystatement = "SELECT DISTINCT IP,Notes FROM %s;" % tableName
        config.cursor.execute(mystatement)
        ips = config.cursor.fetchall()
        config.mydb.commit()
    except:
        return ""
    return ips

    if sorted:
        ip_list        = []
        ip_sorted_list = []
        for i in ips:
            ip_list.append(str(i[0]))
        ip_sorted_list = sorted(ip_list, key=lambda ip: struct.unpack("!L", inet_aton(ip))[0])
        return ip_sorted_list


def lockTable(tableName):
    try:
        config.mydb.ping(True)
        mystatement = "LOCK TABLES %s WRITE;" % tableName
        config.cursor.execute(mystatement)
        config.mydb.commit()
        writeLog(9, "action=\"lock db table\" msg=\"%s\"" % tableName )
    except:
        writeLog(1, "action=\"lock db table\" msg=\"error: %s %s\"" % (tableName, sys.exc_info()[1]))
        return False

    return True

def unlockTable():
    try:
        config.mydb.ping(True)
        mystatement = "UNLOCK TABLES;"
        config.cursor.execute(mystatement)
        config.mydb.commit()
        writeLog(9, "action=\"unlock db table\" msg=success" )
    except:
        writeLog(9, "action=\"unlock db table\" msg=\"error: %s\"" % (sys.exc_info()[1]))
        return False

    return True


def splitLines(foo):
    prevnl = -1
    while True:
      nextnl = foo.find('\n', prevnl + 1)
      if nextnl < 0: break
      yield foo[prevnl + 1:nextnl]
      prevnl = nextnl


def getFwEntries():
    fwLineNumber = []
    fwIpAndCidr  = []
    if config.fwType == "iptables":

        out = subprocess.run(['/usr/sbin/iptables', '-n', '-L', 'INPUT', '-w', '10', '--line-numbers'], timeout=15, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        if out.returncode != 0:
            writeLog(1, "action=\"read fw\", msg=\"error: %s\"" % out.stdout.decode('utf-8'))
            return

        for i in list(splitLines(out.stdout.decode('utf-8'))):
            try:
                lineNumber, Rule, Proto, jnk, ipAndCidr, Source = i.split()
                if Rule == "DROP" and ipAndCidr != "0.0.0.0/0":
                    fwLineNumber.append(lineNumber)
                    fwIpAndCidr.append(ipAndCidr)
            except:
                pass

    elif config.fwType == "nft":
        out = subprocess.run(['/usr/sbin/nft', '--handle', 'list', 'chain', 'inet', 'filter', 'ipblock_input'], timeout=15, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        if out.returncode != 0:
            writeLog(1, "action=\"read fw\", msg=\"error: %s\"" % out.stdout.decode('utf-8'))
            return -1, -1

        for i in list(splitLines(out.stdout.decode('utf-8'))):
            try:
                ip, saddr, ipAndCidr, Rule, _, _, lineNumber = i.split()
                if (ip == 'ip') and (saddr == 'saddr') and (Rule == "drop") and (ipAndCidr != "@blacklist"):
                    fwLineNumber.append(lineNumber)
                    fwIpAndCidr.append(ipAndCidr)
            except:
                pass

    return fwIpAndCidr, fwLineNumber

def deleteFwEntry(fwEntry):
    if config.fwType == "iptables":
        out = subprocess.run(['/usr/sbin/iptables', '-w', '10', '-D', 'INPUT', fwEntry], timeout=15, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        return out.returncode

    elif config.fwType == "nft":
        out = subprocess.run(['/usr/sbin/nft', 'delete', 'rule', 'inet', 'filter', 'ipblock_input', 'handle', fwEntry], timeout=15, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        return out.returncode

def addFwEntry(newDropRule):
    if config.fwType == "iptables":
        out = subprocess.run(['/usr/sbin/iptables', '-w', '10', '-I', 'INPUT', '-s', newDropRule, '-j', 'DROP'], timeout=15, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        return out.returncode

    elif config.fwType == "nft":
        out = subprocess.run(['/usr/sbin/nft', 'insert', 'rule', 'inet', 'filter', 'ipblock_input', 'ip', 'saddr', newDropRule, 'drop'], timeout=15, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        return out.returncode
