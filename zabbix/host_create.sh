#!/bin/bash


act=$1

 #IP=$1  
 #HOST_NAME=$2
 HOSTGROUP_NAME=$1

 # CONSTANT VARIABLES  
 ERROR='0'  
 ZABBIX_USER='Admin' #Make user with API access and put name here  
 ZABBIX_PASS='zabbix' #Make user with API access and put password here  
 ZABBIX_SERVER='ip_address' #DNS or IP hostname of our Zabbix Server  
 API='http://ip_address/api_jsonrpc.php'  
 HOSTGROUPID=6 #What host group to create the server in  
 TEMPLATEID=10001 #What is the template ID that we want to assign to new Servers?  
 # Authenticate with Zabbix API    
 authenticate() {  
         echo `curl -k -s -H 'Content-Type: application/json-rpc' -d "{\"jsonrpc\": \"2.0\",\"method\":\"user.login\",\"params\":{\"user\":\""${ZABBIX_USER}"\",\"password\":\""${ZABBIX_PASS}"\"},\"auth\": null,\"id\":0}" $API`  
     }   

 scr_exe() {

                if [ x$rc == x ];
                then


                        echo -e "Error in adding host ${HOSTGROUP_NAME} at `date`:\n"
                        echo $output | grep -Po '"message":.*?[^\\]",'
                        echo $output | grep -Po '"data":.*?[^\\]"'
                        exit
                else
                                echo -e "\nHost ${HOSTGROUP_NAME} added successfully\n"
                        #start zabbix agent
                        #service zabbix-agent start
                        exit
                fi
}

 AUTH_TOKEN=`echo $(authenticate)|awk -F',' '{print $2}'|awk -F":" '{print $2}' | sed s/\"//g`

if [ x$act == "host" ]
then

 # Create Host  

 	IP=$2
	HOST_NAME=$3

	if [x$IP == "" && x$HOST_NAME == "" ]
	then

		echo "IP or HOSTNAME no!!"

	else

	 	create_host() {  
        	 echo `curl -k -s -H 'Content-Type: application/json-rpc' -d "{\"jsonrpc\":\"2.0\",\"method\":\"host.create\",\"params\": {\"host\":\"$HOST_NAME\",\"interfaces\": [{\"type\": 1,\"main\": 1,\"useip\": 1,\"ip\": \"$IP\",\"dns\": \"\",\"port\": \"10050\"}],\"groups\": [{\"groupid\": \"$HOSTGROUPID\"}],\"templates\": [{\"templateid\": \"$TEMPLATEID\"}]},\"auth\":\"$AUTH_TOKEN\",\"id\":1}" $API`  
     }	 

		output=$(create_host)
 		rc=`echo $output |grep "hostids"`

		scr_exe
	fi

elif [ x$act == "hostgroup" ]
then
	HOST_NAME=$2

	if  [x$HOST_NAME == "" ]
	then

		echo "HOST_GROUPNAME no!!"
	else
	
		create_hostgroup() {
        	 echo `curl -k -s -H 'Content-Type: application/json-rpc' -d "{\"jsonrpc\":\"2.0\",\"method\":\"hostgroup.create\",\"params\": {\"name\":\"$HOSTGROUP_NAME\"},\"auth\":\"$AUTH_TOKEN\",\"id\":1}" $API`
     }
 
		output=$(create_hostgroup)  
 		rc=`echo $output |grep "groupids"`

		scr_exe
	fi

else

	echo "no parameta"

fi

#	if [ x$act == x ];
#	then
#		echo "no parameta"
#
#	else
#
#		if [ x$rc == x ]; 
#  		then  
#		
#		
#      			echo -e "Error in adding host ${HOSTGROUP_NAME} at `date`:\n"  
#      			echo $output | grep -Po '"message":.*?[^\\]",'  
#      			echo $output | grep -Po '"data":.*?[^\\]"'  
#      			exit  
# 		else  
# 				echo -e "\nHost ${HOSTGROUP_NAME} added successfully\n"  
#      			#start zabbix agent  
#      			#service zabbix-agent start  
#   	   		exit  
# 		fi
#	fi  
