#!/usr/bin/python2.6

import sys,socket
import requests
import commands
import json
import urllib2
import urllib
import re
import psutil
import hashlib

ret = {}

def get_hostname():
        hostname = socket.gethostname()
        return hostname



def port_check():
	ret5 = {}
	status, stdin_lines = commands.getstatusoutput("netstat -plnt |grep -v Active | grep -v Proto | awk '{print $4,$7}'")
	lines = stdin_lines.split('\n') 
	for i in lines:
		list = i.split(" ")
		
		port = re.sub('[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+','',list[0]) 
		#port = port.replace("::1","")
		port = port.replace(":","")
		list2 = i.split("/")
		process = list2[1]

		ret5[port] = process
		#print port,process
	return ret5


def firewall_rule_check():
	ret6 = {}
	#status, stdin_lines = commands.getstatusoutput("iptables -nvL | grep '^Chain INPUT' | grep DROP | wc -l")
	#w = int(stdin_lines)
	#if w > 0:
	#	ret6["AAA"] = "IPTABLE ON"
	#else:
		
	#	ret6["AAA"] = "IPTABLE OFF"
	status, stdin_lines = commands.getstatusoutput("iptables-save | grep -E '\-A GABIA_INPUT|\-A INPUT' | grep '\-j ACCEPT' | grep -v '\-s' | grep -v '\-i lo' | grep -v '\--dport 113' | grep -v '\-p icmp'")
	lines = stdin_lines.split('\n')
	n = 1
	for i in lines:
		n = str(n)
		ret6[n] = i
		n = int(n) + 1 	
	return ret6
	
def iptables_check():
	ret7 = {}
	status, stdin_lines = commands.getstatusoutput("iptables -nvL | grep '^Chain INPUT' | grep DROP | wc -l")
	w = int(stdin_lines)
	if w > 0:
		ret7["AAA"] = "IPTABLE ON"
	else:
		
		ret7["AAA"] = "IPTABLE OFF"
	return ret7
def passwd_complex_check():
	ret71 = {}
	status, stdin_lines = commands.getstatusoutput("cat /etc/pam.d/system-auth | grep 'pam_cracklib.so try_first_pass retry=3 type= minlen=8 dcredit=-1 ucredit=-1 lcredit=-1 ocredit=-1' | grep -v '#' | wc -l")
	w = int(stdin_lines)
	if w > 0:
		ret71["AAA"] = "ON"
	else:
		
		ret71["AAA"] = "OFF"
	return ret71

def user_check():
	ret8 = {}
	status, stdin_lines = commands.getstatusoutput("cat /etc/passwd | grep -E '/bin/sh|/bin/bash' | grep -Ev 'root|mysql' | awk -F':' '{print $1}'")
	lines = stdin_lines.split('\n')
	n = 1 
	for i in lines:
		n = str(n)
		ret8[n] = i 
		n = int(n) + 1
	return ret8
	
def ldap_check():
	ret9 = {}
	status, stdin_lines = commands.getstatusoutput("find /etc/ -type f -name '*ldap.conf' | xargs grep ldap | grep ':URI ldaps://182' | wc -l")
	w = int(stdin_lines)
	if w > 0:
		ret9["AAA"] = "LDAP ON"
	else:
		
		ret9["AAA"] = "LDAP OFF"
	return ret9

def otp_check():
	ret10 = {}
	status, stdin_lines = commands.getstatusoutput("find /etc/ -type f -name 'sshd' | xargs grep 'google_authenticator.so' | grep -v '#' | wc -l");
	z = int(stdin_lines)

	status, stdin_lines = commands.getstatusoutput("find /etc/skel -name '.google*' | wc -l");
	zz = int(stdin_lines)
	w = z + zz

	if w > 1:
		ret10["AAA"] = "OTP ON"
	else:
		
		ret10["AAA"] = "OTP OFF"
	return ret10

def ssh_root_check():
	ret11 = {}
	status, stdin_lines = commands.getstatusoutput("find /etc/ -name 'sshd_config' | xargs grep -i 'PermitRootLogin yes' | grep -v '#' | wc -l");
	w = int(stdin_lines)
	if w > 0:
		ret11["AAA"] = "ssh rootlogin ON"
	else:
		
		ret11["AAA"] = "ssh rootlogin OFF"
	return ret11
#firewall_check()

def group_check():
	ret12 = {}
	status, stdin_lines = commands.getstatusoutput(" cat /etc/group /etc/passwd | awk -F':' '{if ($3 == '0') print $1}' | grep -wv 'root'")
	lines = stdin_lines.split('\n')
	n = 1 
	for i in lines:
		n = str(n)
		ret12[n] = i 
		n = int(n) + 1
	return ret12

def date():
	ret13 = {}
	#status, stdin_lines = commands.getstatusoutput("date +%y\-%m\-%d\ %H\:%M\:%S")
	status, stdin_lines = commands.getstatusoutput("date +%y/%m/%d\ %H:%M:%S")
	lines = stdin_lines.split('\n')
	date = lines[0] 
	#date = "aaaa/"
	ret13['A'] = date
	return ret13

def last_login():
	ret14 = {}
	#status, stdin_lines = commands.getstatusoutput("date +%y\-%m\-%d\ %H\:%M\:%S")
	status, stdin_lines = commands.getstatusoutput("date +%Y%m%d%H%M%S --date='30 days ago'")
	lines = stdin_lines.split('\n')
	date = lines[0] 

	status, stdin_lines = commands.getstatusoutput("last -t %s | wc -l" % date)
	
	#date = "aaaa/"
	ret14['A'] = stdin_lines
	return ret14


def update():
	ret15 = {}
	#status, stdin_lines = commands.getstatusoutput("date +%y\-%m\-%d\ %H\:%M\:%S")
	status, stdin_lines = commands.getstatusoutput("uptime | awk -F',' '{print $1}' | awk -F'up' '{print $2}' | sed -e 's/ //g'")
	lines = stdin_lines.split('\n')
	update = lines[0] 
	#date = "aaaa/"
	ret15['A'] = update
	return ret15

def getipaddr():
	ret16 = {}
	req = urllib2.Request("http://ipconfig.co.kr")
	res = urllib2.urlopen(req)
	d = res.read()

	m = re.compile('IP Address: [0-9]+\.[0-9]+\.[0-9]+\.[0-9]+')
	list=m.findall(d)[0]
	list2=list.split(":")
	ipaddr = list2[1].replace(" ","")

	ret16['ipaddr'] = ipaddr
	return ret16

def sess_time():
        ret17 = {}
        status, stdin_lines = commands.getstatusoutput("grep 'TMOUT' /etc/profile /root/.bash_profile | grep -v '#' | wc -l")

        w = int(stdin_lines)
        if w > 0:
                ret17["AAA"] = "TMOUT ON"
        else:

                ret17["AAA"] = "TMOUT OFF"
        return ret17



ret['srv_id'] = get_hostname()
ret['date'] = date()
ret['port_process_info'] = port_check()
ret['firewall_rule_check'] = firewall_rule_check()
ret['iptables_check'] = iptables_check()
ret['user_check'] = user_check()
ret['ldap_check'] = ldap_check()
ret['otp_check'] = otp_check()
ret['ssh_root_check'] = ssh_root_check()
ret['group_check'] = group_check()
ret['passwd_complex_check'] = passwd_complex_check()
ret['date'] = date()
ret['last_login'] = last_login()
ret['update'] = update()
ret['ipaddr'] = getipaddr()
ret['sess_time'] = sess_time()
#ret['mem_usage'] = mem()




data = urllib.urlencode(ret)
#ret['count'] = resource()
#ret['srv_ids'] = get_hostname()
#ret['count'] = get_mem_cpu()
#ret['disk_percent'] = get_disk()


print ret

authstr = get_hostname() + "infra0000009"
sendstr = hashlib.md5(authstr).hexdigest()

req = urllib2.Request("http://192.168.10.20:4000/infoapi.php", data , {'Gabia':sendstr})
res = urllib2.urlopen(req)
d = res.read()
print d 


#data = {key: str(value) for key,value in ret.items()}

#print r.text.encode('utf-8')
#print r.status_code

#print ret



