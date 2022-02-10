##############################
### Triage script for RHEL ###
##############################

###Run this script with root permission###

#/var/log --> including Application, System, Security, audit which are covering the incident time frame.
###On the linux servers, the applications usually keep their logs in their specific folder. However some applications use /var/log folder like Linux apache access logs /var/log/httpd/access_log 
#Journal CTL.SOS Report.
#Get list of all connections.
#Get list of all open files.
#Running processes and services--> List of all running processes.
#Service start-up scripts (/etc/inittab, /etc/init.d, /etc/rc.d etc.)
#List of scheduled tasks (cron jobs)
#Command history
#User lists in /etc/passwd and their group membership and their privilege (suders etc.)
#$HOME/.ssh/authorized_keys entries
#List of %TEMP% folder files
#Get Performance metrics
#Get all open ports
##########################################################################################

#######Set up the folders#######
hostname=`hostname`
filename="$hostname+$(date +%Y%m%d)"
echo "Created folder name: $filename"
mainPath="/tmp/$filename"
echo "Triage path: $mainPath"
mkdir $mainPath
mkdir $mainPath/history 
mkdir $mainPath/user_permission 
mkdir $mainPath/ssh_keys
mkdir $mainPath/network
mkdir $mainPath/process
mkdir $mainPath/process/cron
mkdir $mainPath/var_log

#######Copy of the logs#######
echo "Logs (var/log/) are being copied"
cp -R /var/log/ $mainPath/var_log/ 2>/dev/null


######Network Info&Connections#######
echo "Network informations are being prepared"
echo "############################################" > $mainPath/network/network_info.txt 2>/dev/null
echo "############IFCONFIG Information############" >> $mainPath/network/network_info.txt 2>/dev/null
echo "############################################" >> $mainPath/network/network_info.txt 2>/dev/null
ifconfig -a >> $mainPath/network/network_info.txt 2>/dev/null

echo "############################################" > $mainPath/network/get_all_connections.txt 2>/dev/null
echo "#######NETSTAT -46pan command output########" >> $mainPath/network/get_all_connections.txt 2>/dev/null
echo "############################################" >> $mainPath/network/get_all_connections.txt 2>/dev/null
netstat -46pan >> $mainPath/network/get_all_connections.txt 2>/dev/null
echo "############################################" >> $mainPath/network/get_all_connections.txt 2>/dev/null
echo "##########lsof -ai command output###########" >> $mainPath/network/get_all_connections.txt 2>/dev/null
echo "############################################" >> $mainPath/network/get_all_connections.txt 2>/dev/null
lsof -ai >> $mainPath/network/get_all_connections.txt 2>/dev/null

echo "############################################" > $mainPath/network/get_open_ports.txt 2>/dev/null
echo "#######NETSTAT -ltup command output#########" >> $mainPath/network/get_open_ports.txt 2>/dev/null
echo "############################################" >> $mainPath/network/get_open_ports.txt 2>/dev/null
netstat -ltup >> $mainPath/network/get_open_ports.txt 2>/dev/null


#######Get open files & Services & Running Process#######
echo "Open files, Service status and running processes are being preprared"
echo "############################################" > $mainPath/process/get_open_files.txt 2>/dev/null
echo "###########LSOF command output##############" >> $mainPath/process/get_open_files.txt 2>/dev/null
echo "############################################" >> $mainPath/process/get_open_files.txt 2>/dev/null
lsof >> $mainPath/process/get_open_files.txt 2>/dev/null

echo "############################################" > $mainPath/process/get_service_status.txt 2>/dev/null
echo "####systemctl list-units command output#####" >> $mainPath/process/get_service_status.txt 2>/dev/null
echo "############################################" >> $mainPath/process/get_service_status.txt 2>/dev/null
systemctl list-units --type=service >> $mainPath/process/get_service_status.txt 2>/dev/null

echo "############################################" > $mainPath/process/get_running_process.txt 2>/dev/null
echo "##########ps axjf command output############" >> $mainPath/process/get_running_process.txt 2>/dev/null
echo "############################################" >> $mainPath/process/get_running_process.txt 2>/dev/null
ps axjf >> $mainPath/process/get_running_process.txt 2>/dev/null

cp /etc/inittab $mainPath/process/etc_inittab 2>/dev/null
cp /etc/init.d $mainPath/process/etc_init_d 2>/dev/null
cp /etc/rc.d $mainPath/process/etc_rc_d 2>/dev/null
cp -R /etc/cron* $mainPath/process/cron/ 2>/dev/null
crontab -l > $mainPath/process/cron/cronjob_root.txt


#######Users & Permissions & History & SSH Keys#######
echo "users, rights, history and ssh keys are being prepared"
cat /etc/passwd | grep '/bin/bash' > $mainPath/user_permission/user_list.txt 2>/dev/null
cat /etc/group > $mainPath/user_permission/etc_group.txt 2>/dev/null
cat /etc/sudoers > $mainPath/user_permission/etc_sudoers.txt 2>/dev/null

for directory in $(cat /etc/passwd | grep '/bin/bash' | awk -F":" '{print$6}')
do
        user=$(cat /etc/passwd | grep $directory | awk -F":" '{print$1}')
        crontab -l -u $user > $mainPath/process/cron/cronjob_$user.txt 2>/dev/null
        cp $directory/.bash_history $mainPath/history/history_$user
	cp $directory/.ssh/authorized_keys $mainPath/ssh_keys/authorized_keys_$user
done


#######TEMP Folder#######
echo "list of files udner TMP folder are being prepared"
ls -la /tmp/* > $mainPath/tmp_folder.txt 2>/dev/null


#######Performance Monitoring#######
echo "Performance metrics are being prepared"
echo "############################################" > $mainPath/top-5iterations.txt 2>/dev/null
echo "########TOP -b -n 5 command output##########" >> $mainPath/top-5iterations.txt 2>/dev/null
echo "############################################" >> $mainPath/top-5iterations.txt 2>/dev/null
top -b -n 5 >> $mainPath/top-5iterations.txt 2>/dev/null

echo "Triage preparation is finished. The folder is being compressed."
tar cvzf /tmp/$filename.tgz $mainPath 
echo "Triage file under /tmp/ folder is ready to share with SDC Teams at sdc.europe@ing.com"
echo "...FINISHED..."
