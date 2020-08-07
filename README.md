IP blocker utility
==================
This utility is a multi-host ipblocker.  Each host can monitor various real services or honeypot services, then report failed login attempts to a central mysql database.  A central script then takes all the 'suspects' and generates a block list for hosts.  The logs are Splunk friendly, so you can create really cool graphs and do all the other cool thinks with Splunk (alerting, reports, etc).

Documentation
-------------
This documentation is in early stages.  Much more information to come...

Utilities
---------
* ipblocker
  * This service/script gets the list of rules from the database then runs iptables or nftables to block ips.
* svc-sshd
  * This service/script monitors the sshd audit or auth logs and updates the database with failed login attempts.
* svc-mariadb
  * This service/script monitors the mysql/mariadb error logs and updates the database with failed login attempts.
* honeypot-http
  * This low interaction httpd honeypot service/script monitors httpd connetions and updates the database with connection attempts. 
* honeypot-sshd
  * This low interaction sshd honeypot service/script monitors sshd connetions and updates the database with connection attempts. 
* honeypot-sockets
  * This no interaction honeypot service/script monitors a configurable list of ports and updates the database with connection attempts.
* ipblock-master
  * This is the controller script that reads all the 'suspects' and generates a block list.
  * Rules in the config are used to determine when to block based on number of failed logins per number of minutes.
  * Rules in the config are used to sort and combine the ip addresses into CIDRs to block.
