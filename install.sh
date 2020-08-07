#!/bin/bash

usrLenLim=31                # Max username length for mariadb accounts
rateLimit=6                 # Rate Limit for nft
limitPorts="5601 9200 "     # Default limit ports


grep -q Debian /etc/os-release
if [ $? -eq 0 ];then
  OS_family="Debian"
else
  OS_family="RedHat"
fi
  
# -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
#                  Questions
# -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
echo -e "\nInstall Environment (dev): \c"
read env
if [[ "${env}" == "" ]];then
  env="dev"
fi

echo -e "Is this the ipblock master? (y/n): \c"
while [ "$isMaster" != "y" -a "$isMaster" != "n" ];do
  read isMaster
done

echo -e "Install ssh login monitoring? (y/n): \c"
while [ "$monitorSsh" != "y" -a "$monitorSsh" != "n" ];do
  read monitorSsh
done
if [[ "$monitorSsh" == "y" ]];then
  if [[ -f /var/log/audit/audit.log ]];then
    sshConfTemplate="svc-sshd.audit"
  elif [[ -f /var/log/auth.log ]];then
    sshConfTemplate="svc-sshd.auth"
  else
    sshConfTemplate="svc-sshd.auth"
    echo "WARNING:  Unable to determine best ssh log file to monitor.  You MUST update /etc/ipblock/svc-sshd manually"
  fi
fi

echo -e "Install mariadb login monitoring? (y/n): \c"
while [ "$monitorMariadb" != "y" -a "$monitorMariadb" != "n" ];do
  read monitorMariadb
done
if [[ "$monitorMariadb" == "y" ]];then
  if [ -f /var/log/mariadb/mariadb.log ];then
    mariadbLogFile="/var/log/mariadb/mariadb.log"
  elif [ -f /var/log/mysql/error.log ];then
    mariadbLogFile="/var/log/mysql/error.log"
  else
    echo "Mariadb logfile full path: \c"
    read mariadbLogFile
  fi
  mariadbLogFile=`echo ${mariadbLogFile} |sed 's|/|\\\/|g'`
fi


echo -e "Install a low interaction sshd honeypot? (y/n): \c"
while [ "$isSshdHoneypot" != "y" -a "$isSshdHoneypot" != "n" ];do
  read isSshdHoneypot
done
if [[ "$isSshdHoneypot" == "y" ]];then
  echo -e "Low interaction sshd honeypot port? : \c"
  SshdHoneypotPort=0
  while [ "$SshdHoneypotPort" -lt 1 -o "$SshdHoneypotPort" -gt 65535 ];do
    read SshdHoneypotPort
  done
fi

echo -e "Install a low interaction httpd honeypot? (y/n): \c"
while [ "$isHttpdHoneypot" != "y" -a "$isHttpdHoneypot" != "n" ];do
  read isHttpdHoneypot
done
if [[ "$isHttpdHoneypot" == "y" ]];then
  echo -e "Low interaction httpd honeypot port? : \c"
  httpdHoneypotPort=0
  while [ "$httpdHoneypotPort" -lt 1 -o "$httpdHoneypotPort" -gt 65535 ];do
    read httpdHoneypotPort
  done
fi

echo -e "Install a no interaction port based honeypot? (y/n): \c"
while [ "$isHoneypot" != "y" -a "$isHoneypot" != "n" ];do
  read isHoneypot
done

echo -e "Block ips on this system using iptables/nftables? (y/n): \c"
while [ "$isIpblocker" != "y" -a "$isIpblocker" != "n" ];do
  read isIpblocker
done


echo -e "What is the mysql hostname(or ip): \c"
read mysqlhost

echo -e "mysql port(3306): \c"
read mysqlport
if [[ "${mysqlport}" == "" ]];then
  mysqlport=3306
fi

echo -e "mysql root account: \c"
read rootUser

echo -e "mysql ${rootUser} password: \c"
stty -echo
read rootPW
stty echo


echo -e "\n\n"
echo "Environment                  : $env"
echo "Is this the ipblock master   : $isMaster"
echo "Install ssh login monitoring : $monitorSsh"
echo "Install mariadb monitoring   : $monitorMariadb"
if [[ "$monitorMariadb" == "y" ]];then
  echo "             mariadb logfile : $mariadbLogFile"
fi
echo "Install a sshd honeypot      : $isSshdHoneypot $SshdHoneypotPort"
echo "Install a httpd honeypot     : $isHttpdHoneypot $httpdHoneypotPort"
echo "Install a simple honeypot    : $isHoneypot"
echo "Block ips on this system     : $isIpblocker"
echo "mysql hostname               : $mysqlhost"
echo "mysql port                   : $mysqlport"
echo "mysql root account           : $rootUser"
echo "mysql root pw                : ********"

echo -e "\nReady to install ipblock components? (y/n): \c"
while [ "$Install" != "y" -a "$Install" != "n" ];do
  read Install
done

if [[ "$Install"  == "n" ]];then
  echo "aborted..."
  exit
fi


# -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
#                  Do Install
# -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
mkdir -p /etc/ipblock
chmod 700 /etc/ipblock

mkdir -p /usr/local/bin/ipblock
chmod 700 /usr/local/bin/ipblock

if [ -f ipblock/ipblockHelpers.py ];then
  cp ipblock/* /usr/local/bin/ipblock
  chmod 700 /usr/local/bin/ipblock/*
else
  echo "Cannot find ipblock source files to install..."
  exit 1
fi


#
#  Install dependancies
#
if [[ $OS_family == "Debian" ]];then
  apt -y install python3 python3-dev python3-gssapi libkrb5-dev mariadb-client uuid-runtime
else
  yum install -y python3 python3-devel python3-gssapi krb5-devel mariadb
fi

pip3 install -r requirements.txt

#
#  Check if we can access DB using supplied creds
echo "show tables" |mysql -h${mysqlhost} -u${rootUser} -p${rootPW} --port=${mysqlport} --ssl ipblock >/dev/null
if [ $? -ne 0 ];then
  echo "Unable to access DB...  Unable to continue."
  exit 1
fi


NumTables=`echo "show tables" |mysql -h${mysqlhost} -u${rootUser} -p${rootPW} --port=${mysqlport} --ssl ipblock|grep -e allow_${env} -e block_${env} -e drop_${env} -e suspect_${env} |wc -l`
if [[ $NumTables != 4 ]];then
  echo -e "Tables do not exist in DB.  Create them? (y/n): \c"
  while [ "$createDB" != "y" -a "$createDB" != "n" ];do
    read createDB
  done

  echo "not yet implemented..."
  exit
fi


# -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
#                  Install Master
# -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
if [[ "$isMaster" == "y" ]];then
  mysqlpass=$(uuidgen)
  mysqlUser=`echo "ipblock-master-${env}" |cut -c-${usrLenLim}`
  echo "DROP USER '${mysqlUser}';" |mysql -h${mysqlhost} -u${rootUser} -p${rootPW} --port=${mysqlport} --ssl 2>/dev/null
  echo "GRANT all privileges ON ipblock.* TO '${mysqlUser}'@'%' IDENTIFIED BY '${mysqlpass}' REQUIRE SSL;" |mysql -h${mysqlhost} -u${rootUser} -p${rootPW} --port=${mysqlport} --ssl

  sed -e "s/\${env}/${env}/g" -e "s/\${mysqlhost}/${mysqlhost}/" -e "s/\${mysqlUser}/${mysqlUser}/" \
      -e "s/\${mysqlpass}/${mysqlpass}/" -e "s/\${mysqlport}/${mysqlport}/" etc/conf.d/master >/etc/ipblock/master

  cp etc/systemd/ipblock-master.service /etc/systemd/system
  chmod 600 /etc/systemd/system/ipblock-master.service
  chmod 600 /etc/ipblock/master
  systemctl daemon-reload
  systemctl enable ipblock-master
  systemctl restart ipblock-master

fi



# -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
#                  Install monitors
# -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
if [[ "$monitorSsh" == "y" ||  "$monitorMariadb" == "y" || "$isHoneypot" == "y" || "$isSshdHoneypot" == "y" || "$isHttpdHoneypot" == "y" ]];then
  mkdir -p /var/lib/ipblock
  chmod 700 /var/lib/ipblock
  mysqlpass=$(uuidgen)
  hst=`hostname -s |cut -c-12`
  mysqlUser=`echo "ipblock-${hst}-${env}" |cut -c-${usrLenLim}`
  echo "DROP USER '${mysqlUser}';" |mysql -h${mysqlhost} -u${rootUser} -p${rootPW} --port=${mysqlport} --ssl 2>/dev/null
  echo "GRANT INSERT ON ipblock.suspect_${env} TO '${mysqlUser}'@'%' IDENTIFIED BY '${mysqlpass}' REQUIRE SSL;" |mysql -h${mysqlhost} -u${rootUser} -p${rootPW} --port=${mysqlport} --ssl
fi

if [[ "$monitorSsh" == "y" ]];then
  sed -e "s/\${env}/${env}/g" -e "s/\${mysqlhost}/${mysqlhost}/" -e "s/\${mysqlUser}/${mysqlUser}/" \
      -e "s/\${mysqlpass}/${mysqlpass}/" -e "s/\${mysqlport}/${mysqlport}/" etc/conf.d/${sshConfTemplate} >/etc/ipblock/svc-sshd

  limitPorts="${limitPorts} 22"

  cp etc/systemd/ipblock-svc-sshd.service /etc/systemd/system
  chmod 600 /etc/systemd/system/ipblock-svc-sshd.service
  chmod 600 /etc/ipblock/svc-sshd
  systemctl daemon-reload
  systemctl enable ipblock-svc-sshd.service
  systemctl restart ipblock-svc-sshd.service
fi


if [[ "$monitorMariadb" == "y" ]];then
  sed -e "s/\${env}/${env}/g" -e "s/\${mysqlhost}/${mysqlhost}/" -e "s/\${mysqlUser}/${mysqlUser}/" \
      -e "s/\${mysqlpass}/${mysqlpass}/" -e "s/\${mysqlport}/${mysqlport}/" \
      -e "s/\${mariadbLogFile}/${mariadbLogFile}/g" etc/conf.d/svc-mariadb >/etc/ipblock/svc-mariadb

  limitPorts="${limitPorts} 3306"

  cp etc/systemd/ipblock-svc-mariadb.service /etc/systemd/system
  chmod 600 /etc/systemd/system/ipblock-svc-mariadb.service
  chmod 600 /etc/ipblock/svc-mariadb
  systemctl daemon-reload
  systemctl enable ipblock-svc-mariadb.service
  systemctl restart ipblock-svc-mariadb.service
fi


if [[ "$isHttpdHoneypot" == "y" ]];then
  sed -e "s/\${env}/${env}/g" -e "s/\${mysqlhost}/${mysqlhost}/" -e "s/\${mysqlUser}/${mysqlUser}/" \
      -e "s/\${mysqlpass}/${mysqlpass}/" -e "s/\${mysqlport}/${mysqlport}/" \
      -e "s/\${httpdHoneypotPort}/${httpdHoneypotPort}/g" etc/conf.d/honeypot-httpd >/etc/ipblock/honeypot-httpd

  limitPorts="${limitPorts} ${httpdHoneypotPort}"

  cp etc/systemd/ipblock-honeypot-httpd.service /etc/systemd/system
  chmod 600 /etc/systemd/system/ipblock-honeypot-httpd.service
  chmod 600 /etc/ipblock/honeypot-httpd
  systemctl daemon-reload
  systemctl enable ipblock-honeypot-httpd.service
  systemctl restart ipblock-honeypot-httpd.service
fi


if [[ "$isSshdHoneypot" == "y" ]];then
  pip3 install paramiko          # for honeypot-sshd
  pip3 install python-gssapi     # for honeypot-sshd

  if [ ! -f /var/lib/ipblock/ssh_host_rsa_key ];then
    ssh-keygen -N '' -t rsa -f /var/lib/ipblock/ssh_host_rsa_key
  fi
  chmod 600 /var/lib/ipblock/ssh_host_rsa_key*

  sed -e "s/\${env}/${env}/g" -e "s/\${mysqlhost}/${mysqlhost}/" -e "s/\${mysqlUser}/${mysqlUser}/" \
      -e "s/\${mysqlpass}/${mysqlpass}/" -e "s/\${mysqlport}/${mysqlport}/" \
      -e "s/\${SshdHoneypotPort}/${SshdHoneypotPort}/g" etc/conf.d/honeypot-sshd >/etc/ipblock/honeypot-sshd

  limitPorts="${limitPorts} ${SshdHoneypotPort}"

  cp etc/systemd/ipblock-honeypot-sshd.service /etc/systemd/system
  chmod 600 /etc/systemd/system/ipblock-honeypot-sshd.service
  chmod 600 /etc/ipblock/honeypot-sshd
  systemctl daemon-reload
  systemctl enable ipblock-honeypot-sshd.service
  systemctl restart ipblock-honeypot-sshd.service
fi



if [[ "$isHoneypot" == "y" ]];then
  sed -e "s/\${env}/${env}/g" -e "s/\${mysqlhost}/${mysqlhost}/" -e "s/\${mysqlUser}/${mysqlUser}/" \
      -e "s/\${mysqlpass}/${mysqlpass}/" -e "s/\${mysqlport}/${mysqlport}/" etc/conf.d/honeypot-sockets >/etc/ipblock/honeypot-sockets

  limitPorts="${limitPorts} 20 21 23 25 53 69 80 109 110 123 137 139 389 465 512 513 514 515 587 3306"

  cp etc/systemd/ipblock-honeypot-sockets.service /etc/systemd/system
  chmod 600 /etc/systemd/system/ipblock-honeypot-sockets.service
  chmod 600 /etc/ipblock/honeypot-sockets
  systemctl daemon-reload
  systemctl enable ipblock-honeypot-sockets.service
  systemctl restart ipblock-honeypot-sockets.service
fi


# -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
#                Install iptables blocker
# -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
if [[ "$isIpblocker" == "y" ]];then
  mysqlpass=$(uuidgen)
  hst=`hostname -s`
  mysqlUser=`echo "ipblocker-${hst}" |cut -c-${usrLenLim}`
  echo "DROP USER '${mysqlUser}';" |mysql -h${mysqlhost} -u${rootUser} -p${rootPW} --port=${mysqlport} --ssl 2>/dev/null
  echo "GRANT SELECT ON ipblock.drop_${env} TO '${mysqlUser}'@'%' IDENTIFIED BY '${mysqlpass}' REQUIRE SSL;" |mysql -h${mysqlhost} -u${rootUser} -p${rootPW} --port=${mysqlport} --ssl

  sed -e "s/\${env}/${env}/g" -e "s/\${mysqlhost}/${mysqlhost}/" -e "s/\${mysqlUser}/${mysqlUser}/" \
      -e "s/\${mysqlpass}/${mysqlpass}/" -e "s/\${mysqlport}/${mysqlport}/" etc/conf.d/ipblocker >/etc/ipblock/ipblocker

  # Check if system is using nft
  if [ -f /etc/sysconfig/nftables.conf ];then
    grep -q 'include "/etc/nftables/ipblock-filter.nft' /etc/sysconfig/nftables.conf
    if [ $? -ne 0 ];then
      echo 'include "/etc/nftables/ipblock-filter.nft"' >>/etc/sysconfig/nftables.conf
    fi

    cp etc/ipblock-filter.nft /etc/nftables/ipblock-filter.nft

    for i in ${limitPorts}
    do
      sed -i "/ip saddr @blacklist drop;/a tcp dport ${i} ct state new limit rate over ${rateLimit}\/minute add @blacklist { ip saddr };" /etc/nftables/ipblock-filter.nft
    done

    systemctl restart nftables
  fi

  cp etc/systemd/ipblocker.service /etc/systemd/system
  chmod 600 /etc/systemd/system/ipblocker.service
  chmod 600 /etc/ipblock/ipblocker
  systemctl daemon-reload
  systemctl enable ipblocker
  systemctl restart ipblocker
fi

echo "All Done..."
