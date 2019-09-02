#!/bin/bash
# desc: CentOS initialization
# 比如：curl https://resource.haier.net/download/init/Centos-init.sh | bash -s base
# Author: hehan
# Mail: hehan@haier.com
# Last Update: 2019.07.31
#=================================================================

#-------*****************-------
#--1--此脚本需要root用户执行
#--2--需要有/apps 和 /export目录
#--3--并且确认yum不要有什么后台进程在运行
#-------*****************-------


cat << EOF
 +--------------------------------------------------------------+  
 |              === Welcome to  System init ===                 |  
 +--------------------------------------------------------------+  
EOF

echo -e "\033[31m 这个是Centos系统初始化脚本，请慎重运行！ press ctrl+C to cancel \033[0m"
sleep 5

##############从此处开始需要编辑###########

#统一使用生产资源服务器下的jdk和tomcat，默认初始化jdk1.7.0_60，jdk使用的jdk1.8.0_172
JDK7_PATH='https://resource.haier.net/download/init/java/jdk1.7.tar.gz'
JDK8_PATH='https://resource.haier.net/download/init/java/jdk1.8.tar.gz'

#DNS设置
DNS1=""
DNS2=""
DNS3=''
DNS4=''

#salt master地址
SALT_MASTER='10.159.32.200'

#主机名
HOSTNAME="node-01"

#zabbix 源版本
ZABBIX_REPO_VERSION='3.4'
#zabbix server
ZBX_SERVER='10.159.32.89'
#zabbix 安装版本
ZABBIX_AGENT_VERSION='3.4.11'

#mysql默认管理密码
MYSQL_PASSWORD=mysql0828

##############从此处开始停止编辑###########

#判断是否为root用，platform是否为X64
if  [ $(id -u) -gt 0 ]; then
    echo "please use root run the script!"
    exit 1
fi
platform=`uname -i`
osversion=`cat /etc/redhat-release | awk '{print $1}'`
if [[ $platform != "x86_64" ||  $osversion != "CentOS" ]];then
    echo "Error this script is only for 64bit and CentOS Operating System !"
    exit 1
fi
    echo "The platform is ok"

sleep 3

#判断是否存在/apps和/export目录，没有的话退出
if [[ -d /apps && -d /export ]]
then
	echo "OK /apps and /export is fine"
else
	echo 'Sorry. you do not have a /apps and /export directory'
	exit 1
fi


v=`cat /etc/redhat-release|sed -r 's/.* ([0-9]+)\..*/\1/'`
 
if [ $v -eq 6 ]; then
 
    echo "系统版本：Centos 6"
 
fi
 
if [ $v -eq 7 ]; then
 
    echo "系统版本：Centos 7"
 
fi

#获取本机ip地址
ipaddr=`ifconfig |grep team0 -A 1|grep inet|awk '{print $2}'`
  if [ "$ipaddr" =  "" ]
  then
    ipaddr=`ifconfig |grep bond0 -A 1|grep inet|awk '{print $2}'|awk -F':' '{print $2}'`
  fi
  if  [ "$ipaddr" =  "" ]
  then
	ipaddr=`/sbin/ifconfig | grep 'inet ' | awk '{print $2}' | sed -e '/127\.0\.0\.1/d' | head -n 1`
  fi
  if  [ "$ipaddr" =  "" ]
  then
	ipaddr=`ip a |grep -E "team0$|bond0$|eth0$|ens160$" |grep "inet" |awk '{print $2}' |awk -v FS="/" '{print $1}'`
  fi
echo "服务器IP地址：$ipaddr"

#
function hostname_config() {
	#hostnamectl set-hostname aaa
	if [ "$HOSTNAME" == "" ];then
		echo "The host name is empty."
		exit 1
	else     
        echo "HostName is $HOSTNAME"
        hostnamectl set-hostname $HOSTNAME
	fi
	sleep 3
	echo "-------计算机名修改完成-------"
}

function firewall_config() {
    # 禁用selinux
    sed -i 's/SELINUX=enforcing/SELINUX=disabled/g' /etc/selinux/config
    setenforce 0
	
	sed -i 's/#UseDNS yes/UseDNS no/g' /etc/ssh/sshd_config
	
    # 请根据具体情况来决定是否关闭防火墙
    if [ $v -eq 6 ];then
		echo "-------修改Centos 6 防火墙策略-------"
		service iptables start
		chkconfig iptables on
		#调整默认策略（默认拒绝所有访问，改成允许所有访问）
		iptables -P INPUT ACCEPT
		iptables -P OUTPUT ACCEPT
		service iptables save
		service iptables restart
		#iptables -P OUTPUT ACCEPT
		/etc/init.d/sshd restart
	fi

	if [ $v -eq 7 ];then
		echo "-------修改Centos 7 防火墙策略-------"
		systemctl restart firewalld.service
		systemctl enable firewalld.service
		#调整默认策略（默认拒绝所有访问，改成允许所有访问）：
		firewall-cmd --permanent --zone=public --set-target=ACCEPT
		firewall-cmd --reload
		systemctl restart sshd
	fi
	echo "-------防火墙初始化完成-------"
}

function yum_config() {
	#yum instll wget
    #cd /etc/yum.repos.d/ && mkdir bak && mv -f *.repo bak/
    #wget -O /etc/yum.repos.d/CentOS-Base.repo http://mirrors.aliyun.com/repo/Centos-7.repo
    #wget -O /etc/yum.repos.d/epel.repo http://mirrors.aliyun.com/repo/epel-7.repo
    #yum clean all && yum makecache
    #yum -y install iotop iftop net-tools lrzsz gcc gcc-c++ make cmake libxml2-devel openssl-devel curl curl-devel unzip sudo ntp libaio-devel wget vim ncurses-devel autoconf automake zlib-devel  python-devel bash-completion
    
    MIRROR="http://mirrors.aliyun.com"
    #更换yum源为阿里源
    cp /etc/yum.repos.d/CentOS-Base.repo /etc/yum.repos.d/CentOS-Base.repo.backup
    sed -i "s/#baseurl/baseurl/g" /etc/yum.repos.d/CentOS-Base.repo
    sed -i "s/mirrorlist=http/#mirrorlist=http/g" /etc/yum.repos.d/CentOS-Base.repo
    sed -i "s@baseurl=.*/centos@baseurl=$MIRROR/centos@g" /etc/yum.repos.d/CentOS-Base.repo
	yum clean all
    yum makecache

    #同步时间
	timedatectl set-local-rtc 1 && timedatectl set-timezone Asia/Shanghai
    yum install -y ntpdate
	ntpdate ntp1.aliyun.com
	hwclock -w

    #配置EPEL源
    #EPEL (Extra Packages for Enterprise Linux) 是由 Fedora Special Interest Group 为企业 Linux 创建、维护和管理的一个高质量附加包集合，适用于但不仅限于 Red Hat Enterprise Linux (RHEL), CentOS, Scientific Linux (SL), Oracle Linux (OL)
    yum install -y epel-release
    cp /etc/yum.repos.d/epel.repo /etc/yum.repos.d/epel.repo.backup
    mv /etc/yum.repos.d/epel-testing.repo /etc/yum.repos.d/epel-testing.repo.backup
    # curl -o /etc/yum.repos.d/epel.repo http://mirrors.aliyun.com/repo/epel-7.repo
    sed -i "s/#baseurl/baseurl/g" /etc/yum.repos.d/epel.repo
    sed -i "s/metalink/#metalink/g" /etc/yum.repos.d/epel.repo
    sed -i "s@baseurl=.*/epel@baseurl=$MIRROR/epel@g" /etc/yum.repos.d/epel.repo

    yum makecache
	#初始化安装服务
	yum install -y net-tools vim telnet unzip tcpdump sysstat gcc gdb wget iotop iftop traceroute tomcat-native cronolog lrzsz apr lsof nmap
	
	#增加普通用户的软件执行权限
	chmod u+s /usr/sbin/tcpdump
	chmod u+s /usr/sbin/iftop
	
	echo "-------YUM源和应用服务初始化完成-------"
}

# 内核优化
function kernel_config() {
	#文件句柄数优化
    cp /etc/security/limits.conf /etc/security/limits.conf.bak
	cat >> /etc/security/limits.conf << EOF
*        soft   nofile       102400
*        hard   nofile       102400
@cloud-user      hard    core            0
@cloud-user      soft    core            0
@cloud-user      hard    nproc           400000
@cloud-user      soft    nproc           300000
@cloud-user      hard    nofile          400000
@cloud-user      soft    nofile          300000
EOF

	cp /etc/security/limits.d/20-nproc.conf /etc/security/limits.d/20-nproc.conf.bak
	cat > /etc/security/limits.d/20-nproc.conf << EOF
# Default limit for number of user's processes to prevent
# accidental fork bombs.
# See rhbz #432903 for reasoning.
 
*          soft    nproc     102400
root       soft    nproc     unlimited
EOF

	#内核参数优化
	cp /etc/sysctl.conf /etc/sysctl.conf.bak
	cat >> /etc/sysctl.conf << EOF
# U+ General Optimize Configuration
fs.file-max = 3260334
vm.swappiness=0
net.core.somaxconn = 8192
net.core.netdev_max_backlog = 2000 
net.core.rmem_default = 131072 
net.core.wmem_default = 131072 
net.core.rmem_max = 131072 
net.core.wmem_max = 131072 
net.ipv4.tcp_rmem = 4096 87380 4194304
net.ipv4.tcp_wmem = 4096 16384 4194304 
net.ipv4.tcp_mem = 6180960 8241280 12361920
net.ipv4.ip_local_port_range = 10000 50000
net.ipv4.tcp_fin_timeout = 15 
net.ipv4.tcp_tw_reuse = 1 
net.ipv4.tcp_tw_recycle = 1 
net.ipv4.tcp_max_syn_backlog = 8192 
net.ipv4.tcp_max_orphans = 2048
net.ipv4.tcp_syncookies = 1
net.nf_conntrack_max = 655350
EOF
/sbin/sysctl -p
    echo "-------limit、sysctl初始化完成-------"
}

function user_add() {
	#创建haieradmin，并允许其用sudo命令时不需要输入密码
    NEWUSER="uplus"
	PASS="rOXFJZhiaACE"
	id $NEWUSER
	if [ $? -eq 0 ] ; then
		echo "$NEWUSER账户已存在，无法创建!"
	else
		useradd $NEWUSER
		echo $PASS | passwd --stdin $NEWUSER
		if [ $? -eq 0 ] ; then
			echo "$NEWUSER账户创建成功！"
			sed -i "/^root/a\$NEWUSER\tALL=(ALL)\tNOPASSWD: ALL" /etc/sudoers
		else
			echo "$NEWUSER账户创建失败！"
		fi
	fi
	
	NEWUSER2="cloud-user"
	PASS2="cloud-user12345"
	id $NEWUSER2
	if [ $? -eq 0 ] ; then
		echo "$NEWUSER2账户已存在，无法创建!"
	else
		useradd $NEWUSER2
		echo $PASS2 | passwd --stdin $NEWUSER2
		if [ $? -eq 0 ] ; then
			echo "$NEWUSER2账户创建成功！"
		else
			echo "$NEWUSER账户创建失败！"
		fi
	fi

	echo "-------系统用户、目录初始化完成-------"
}

function dns_config() {
	#请根据各环境进行配置
	cat > /etc/resolv.conf <<EOF
nameserver $DNS1
nameserver $DNS2
nameserver $DNS3
nameserver $DNS4
EOF
	echo "dns初始化配置完成"
}

#安装jdk和tomcat
function install_jdk_and_tomcat() {
	#统一使用生产资源服务器下的jdk和tomcat，默认初始化jdk1.7.0_60，jdk使用的jdk1.8.0_172
    cd /apps
    wget -O /apps/jdk1.7.tar.gz $JDK7_PATH
    wget -O /apps/jdk1.8.tar.gz $JDK8_PATH
    #wget https://resource.haier.net/download/java/tomcat8.5.tar.gz
    #curl @jenkins-res.uhome.haier.net:60021/ops/deploy_tomcat.sh">ftp://ftpuser:RwtgwZPj@jenkins-res.uhome.haier.net:60021/ops/deploy_tomcat.sh | bash /dev/stdin 750"
    #curl @jenkins-res.uhome.haier.net:60021/ops/deploy_tomcat8.sh">ftp://ftpuser:RwtgwZPj@jenkins-res.uhome.haier.net:60021/ops/deploy_tomcat8.sh | bash /dev/stdin 750"
    tar -xf /apps/jdk1.7.tar.gz -C /apps/
    tar -xf /apps/jdk1.8.tar.gz -C /apps/
    chown -hR cloud-user:cloud-user /apps/jdk1.7
    chown -hR cloud-user:cloud-user /apps/jdk1.8
	cat >> /etc/profile << EOF
export JAVA_HOME=/apps/jdk1.7
export PATH=\$JAVA_HOME/bin:\$PATH
export CLASSPATH=.:\$JAVA_HOME/lib/dt.jar:\$JAVA_HOME/lib/tools.jar
EOF

    source /etc/profile
    rm -f /apps/jdk1.7.tar.gz /apps/jdk1.8.tar.gz
    echo "-------JDK、TOMCAT初始化完成-------"
}

#安装salt-minion 2019-02最新版本
function install_salt_minion() {
	#服务端域名：salt.haier.net
	if [ $v -eq 6 ];then
	    echo "-------执行Centos6 salt安装-------"
		yum install -y https://repo.saltstack.com/yum/redhat/salt-repo-latest.el6.noarch.rpm
		sed -i "s/repo.saltstack.com/mirrors.aliyun.com\/saltstack/g" /etc/yum.repos.d/salt-latest.repo
		yum install -y salt-minion-2019.2.0
		sed -i 's/^master.*/#&/' /etc/salt/minion
		sed -i 's/^id.*/#&/' /etc/salt/minion
		rm -f /etc/salt/pki/minion/*
		sleep 5
		cat >> /etc/salt/minion << EOF
master: $SALT_MASTER
id: $ipaddr
EOF
		chkconfig salt-minion on
		service salt-minion start
	fi
	
	if [ $v -eq 7 ];then
		echo "-------执行Centos7 salt安装-------"
		yum install -y https://repo.saltstack.com/yum/redhat/salt-repo-latest.el7.noarch.rpm
		sed -i "s/repo.saltstack.com/mirrors.aliyun.com\/saltstack/g" /etc/yum.repos.d/salt-latest.repo
		yum install -y salt-minion-2019.2.0
		sed -i 's/^master.*/#&/' /etc/salt/minion
		sed -i 's/^id.*/#&/' /etc/salt/minion
		rm -f /etc/salt/pki/minion/*
		sleep 5
		cat >> /etc/salt/minion << EOF
master: $SALT_MASTER
id: $ipaddr
EOF
		systemctl enable salt-minion
		systemctl restart salt-minion
	fi
	echo "-------Saltstack Minion初始化完成-------"
}

#安装zabbix agent
function install_zabbix_agent() {
	#安装zabbix-agent初始化,不同环境使用注意配置DNS zabbix.haier.net服务端映射
	
	#zabbix-agent
	FTPROOT=ftp://$FTP/upload/software/zabbix
	ZCONF="https://resource.haier.net/download/init/zabbix/zabbix_agentd.conf"
	ZCRON="https://resource.haier.net/download/init/zabbix/crontab/zabbix-crontab.sh"
	TCPCONF="https://resource.haier.net/download/init/zabbix/zabbix_agentd.d/userparameter_tcp.conf"
	
	# install zabbix-agent
	rpm -q zabbix-agent &>/dev/null && ZBXA=1 || ZBXA=0
	if [ $ZBXA == 0 ];then
			if [ $OS == 3 ]  ;then
					OSVER=7
					echo "----OSVER: $OSVER----"
					FTPPATH=$FTPROOT/3.4.11/$OSVER
					ZAGT="zabbix-agent-3.4.11-1.el7.x86_64.rpm"
					ZSDR="zabbix-sender-3.4.11-1.el7.x86_64.rpm"

					# install zabbix-agent
					wget --ftp-user=$FTPUSER --ftp-password=$FTPPASSWD --directory-prefix=$LOCALPATH $FTPPATH/$ZAGT &>/dev/null && echo "----zabbix-agent download successed.----" || echo "----zabbix-agent download failed.----"
					wget --ftp-user=$FTPUSER --ftp-password=$FTPPASSWD --directory-prefix=$LOCALPATH $FTPPATH/$ZSDR &>/dev/null && echo "----zabbix-sender download successed.----" ||echo "----zabbix-sender download failed.----"
					yum -y install $LOCALPATH/$ZAGT $LOCALPATH/$ZSDR &>/dev/null && echo "----zabbix-agent zabbix-sender install seccessed.----"

					# remove rpm file
					rm -f $LOCALPATH/zabbix-agent*.rpm $LOCALPATH/zabbix-sender*.rpm

			elif [ $OS == 2 ];then
					OSVER=6
					echo "----OSVER: $OSVER----"
					FTPPATH=$FTPROOT/3.4.11/$OSVER
					ZAGT="zabbix-agent-3.4.11-1.el6.x86_64.rpm"
					ZSDR="zabbix-sender-3.4.11-1.el6.x86_64.rpm"

					# install zabbix-agent
					wget --ftp-user=$FTPUSER --ftp-password=$FTPPASSWD --directory-prefix=$LOCALPATH $FTPPATH/$ZAGT &>/dev/null && echo "----zabbix-agent download successed.----" || echo "----zabbix-agent download failed.----"
					wget --ftp-user=$FTPUSER --ftp-password=$FTPPASSWD --directory-prefix=$LOCALPATH $FTPPATH/$ZSDR &>/dev/null && echo "----zabbix-sender download successed.----" ||echo "----zabbix-sender download failed.----"
					yum -y install $LOCALPATH/$ZAGT $LOCALPATH/$ZSDR &>/dev/null && echo "----zabbix-agent zabbix-sender install seccessed.----"

					# remove rpm file
					rm -f $LOCALPATH/zabbix-agent*.rpm $LOCALPATH/zabbix-sender*.rpm


			else 
					echo "----OS not support! Exiting...----"
			fi

	else
			echo -e "----$(rpm -q zabbix-agent) already installed.----"
	fi


	# config zabbix-agent
	mv /etc/zabbix/zabbix_agentd.conf{,.ori.$(date +%F)}
	wget --ftp-user=$FTPUSER --ftp-password=$FTPPASSWD --directory-prefix=/etc/zabbix $ZCONF &>/dev/nulll && echo "----zabbix_agentd.conf download successed.----" || echo "----zabbix_agentd.conf download failed.----"
	sed -i "s/^Server=.*$/Server=$ZBX_SERVER/" /etc/zabbix/zabbix_agentd.conf
	sed -i "s/^ServerActive=.*$/ServerActive=$ZBX_SERVER/" /etc/zabbix/zabbix_agentd.conf
	sed -i "s/^Hostname=.*$/Hostname=$LOCALIP/" /etc/zabbix/zabbix_agentd.conf
	echo "----zabbix_agentd.conf update successed.-----"


	# config zabbix-agent tcp status
	if [ ! -f $TCPCONF ];then
			wget --ftp-user=$FTPUSER --ftp-password=$FTPPASSWD --directory-prefix=/etc/zabbix/zabbix_agentd.d $TCPCONF &>/dev/nulll && echo "----userparameter_tcp.conf download successed.----" || echo "----userparameter_tcp.conf download failed.----"
	fi

	# chmod
	chown -R zabbix:zabbix /etc/zabbix



	# start zabbix-agent
	if [ $OS == 3 ];then
			# start zabbix-agent
			systemctl restart zabbix-agent &>/dev/null && echo "----zabbix-agent start successed.----" ||echo "----zabbix-agent start failed.----"
			systemctl enable zabbix-agent &>/dev/null
	elif [ $OS == 2 ];then
			# start zabbix-agent
			service zabbix-agent restart &>/dev/null && echo "----zabbix-agent start successed.----" ||echo "----zabbix-agent start failed.----"
			chkconfig zabbix-agent on &>/dev/null
	else
			echo "----OS not support! Exiting...----"
	fi


	# mkdir bin
	if [ ! -d /etc/zabbix/bin ];then
			mkdir /etc/zabbix/bin
	fi

	# zabbix-agent crontab	
	if [ ! -f /etc/zabbix/bin/zabbix-crontab.sh ];then
			wget --ftp-user=$FTPUSER --ftp-password=$FTPPASSWD --directory-prefix=/etc/zabbix/bin $ZCRON &>/dev/null && echo "----zabbix-crontab.sh download successed.----" || echo "----zabbix-crontab.sh download failed.----" 
			chmod +x /etc/zabbix/bin/zabbix-crontab.sh
			chown -R zabbix:zabbix /etc/zabbix
	fi

	grep "/etc/zabbix/bin/zabbix-crontab.sh" /var/spool/cron/root &>/dev/null && ZC=1 || ZC=0
	if [ $ZC == 0 ];then
			echo '* * * * * /etc/zabbix/bin/zabbix-crontab.sh' >>/var/spool/cron/root
			echo "----zabbix-agent crontab config successed.----"
	else
			echo "----zabbix-agent crontab already exist.----"
	fi

	echo "-------Zabbix agent初始化完成-------"
}

#安装mysql5.7 http://mirrors.tuna.tsinghua.edu.cn/mysql,使用清华大学的源
function install_mysql_and_config() {
    cat > /etc/yum.repos.d/mysql-community.repo << EOF
[mysql-connectors-community]
name=MySQL Connectors Community
baseurl=http://mirrors.tuna.tsinghua.edu.cn/mysql/yum/mysql-connectors-community-el7
enabled=1
gpgcheck=0
gpgkey=file:///etc/pki/rpm-gpg/RPM-GPG-KEY-mysql

[mysql-tools-community]
name=MySQL Tools Community
baseurl=http://mirrors.tuna.tsinghua.edu.cn/mysql/yum/mysql-tools-community-el7
enabled=1
gpgcheck=0
gpgkey=file:///etc/pki/rpm-gpg/RPM-GPG-KEY-mysql

[mysql57-community]
name=MySQL 5.7 Community Server
baseurl=http://mirrors.tuna.tsinghua.edu.cn/mysql/yum/mysql57-community-el7
enabled=1
gpgcheck=0
gpgkey=file:///etc/pki/rpm-gpg/RPM-GPG-KEY-mysql

[mysql80-community]
name=MySQL 8.0 Community Server
baseurl=http://mirrors.tuna.tsinghua.edu.cn/mysql/yum/mysql80-community-el7
enabled=0
gpgcheck=0
gpgkey=file:///etc/pki/rpm-gpg/RPM-GPG-KEY-mysql

EOF

    yum install mysql-community-server -y
    #mysql配置
    if [[ "${MYSQL_PASSWORD}" == "" ]];then
    #root用户密码
    MYSQL_PASSWORD=mysql0828
    fi
    systemctl start mysqld
    systemctl enable mysqld
    passlog=$(grep 'temporary password'  /var/log/mysqld.log)
    pass=${passlog:${#passlog}-12:${#passlog}}
    mysql -uroot -p"${pass}" -e"alter user root@localhost identified by 'QQQqqq111...' " --connect-expired-password
    pass=QQQqqq111...
    mysql -uroot -p"${pass}" -e"set global validate_password_policy=0;" --connect-expired-password
    mysql -uroot -p"${pass}" -e"set global validate_password_length=4;" --connect-expired-password
    mysql -uroot -p"${pass}" -e"set global validate_password_mixed_case_count=0;" --connect-expired-password
    mysql -uroot -p"${pass}" -e"set global validate_password_number_count=0;" --connect-expired-password
    #echo 'enter your mysql password'
    #read password
    mysql -uroot -p"${pass}" -e"set password=password('${MYSQL_PASSWORD}');" --connect-expired-password
    mysql -uroot -p"${MYSQL_PASSWORD}" -e"update mysql.user set host='%' where user='root';" --connect-expired-password
    mysql -uroot -p"${MYSQL_PASSWORD}" -e"flush privileges;" --connect-expired-password

	echo "-------Mysql5.7 初始化安装完成-------"
}

#安装mongodb,使用清华大学的源
function install_mongodb() {
    echo "" > /etc/yum.repos.d/mongodb.repo
    for version in "3.0" "3.2" "3.4" "3.6" "4.0"; do
    cat >> /etc/yum.repos.d/mongodb.repo << EOF
[mongodb-org-$version]
name=MongoDB Repository
baseurl=https://mirrors.tuna.tsinghua.edu.cn/mongodb/yum/el7-$version/
gpgcheck=0
enabled=1

EOF
    done
    yum makecache
    yum install mongodb-org -y

	echo "-------mongodb初始化安装完成-------"
}

#安装docker
function install_docker() {
    yum-config-manager --add-repo https://download.docker.com/linux/centos/docker-ce.repo
    sed -i "s@https://download.docker.com@https://mirrors.aliyun.com/docker-ce@g"  /etc/yum.repos.d/docker-ce.repo
    yum install docker-ce -y
    systemctl start docker
	#配置国内docker加速器
	cat > /etc/docker/daemon.json << EOF
{
  "registry-mirrors": ["https://registry.docker-cn.com"]
}
EOF
	systemctl enable docker
    systemctl restart docker
	
	echo "-------docker初始化安装完成-------"
}

#安装redis
function install_redis() {

    yum install -y http://rpms.remirepo.net/enterprise/remi-release-7.rpm
	yum --enablerepo=remi install -y redis
	#配置redis参数
	cp /etc/redis.conf /etc/redis.conf_bak
	cat > /etc/redis.conf << EOF
daemonize yes 
pidfile "/var/run/redis/redis.pid"
port 4100
tcp-backlog 511
timeout 0
tcp-keepalive 0
loglevel notice
logfile "/var/log/redis/redis.log"
databases 16
save 900 1
save 300 10
save 60 10000
maxmemory 10g
stop-writes-on-bgsave-error yes
rdbcompression yes
rdbchecksum yes
dbfilename "dump.rdb"
dir "/var/lib/redis"
slave-serve-stale-data yes
slave-read-only yes
repl-diskless-sync no
repl-diskless-sync-delay 5
repl-disable-tcp-nodelay no
slave-priority 100
appendonly yes
appendfilename "appendonly.aof"
appendfsync everysec
no-appendfsync-on-rewrite no
auto-aof-rewrite-percentage 100
auto-aof-rewrite-min-size 64mb
aof-load-truncated yes
lua-time-limit 5000
slowlog-log-slower-than 10000
slowlog-max-len 128
latency-monitor-threshold 0
notify-keyspace-events ""
hash-max-ziplist-entries 512
hash-max-ziplist-value 64
list-max-ziplist-entries 512
list-max-ziplist-value 64
set-max-intset-entries 512
zset-max-ziplist-entries 128
zset-max-ziplist-value 64
hll-sparse-max-bytes 3000
activerehashing yes
client-output-buffer-limit normal 0 0 0
client-output-buffer-limit slave 256mb 64mb 60
client-output-buffer-limit pubsub 32mb 8mb 60
hz 10
aof-rewrite-incremental-fsync yes
#masterauth "LQi#czFe$!"
#requirepass "LQi#czFe$!"
# Generated by CONFIG REWRITE
#protected-mode no
EOF

	#Sentinel的配置
	cp /etc/redis-sentinel.conf /etc/redis-sentinel.conf_bak
	cat > /etc/redis-sentinel.conf << EOF
port 4200
daemonize yes
protected-mode no
logfile "/var/log/redis/sentinel.log"
pidfile "/var/run/redis/sentinel.pid"
dir "/tmp"

sentinel monitor mymaster 127.0.0.1 4100 1
sentinel down-after-milliseconds mymaster 5000    
sentinel config-epoch mymaster 10                             
sentinel parallel-syncs mymaster 1 
EOF
    
	#Redis的启动
	#systemctl enable redis.service
    #systemctl restart redis.service
	#手动启动
	#redis-server /etc/redis.conf
	#启动redis sentinel监听
	#systemctl enable redis-sentinel.service
	#systemctl restart redis-sentinel.service
	#手动启动
	#redis-sentinel /etc/redis-sentinel.conf
	
	echo "-------redis初始化安装完成-------"
}

#安装Python3环境
function install_python3() {
	#安装依赖
    yum -y install wget libselinux-python sqlite-devel xz gcc automake zlib-devel openssl-devel epel-release git
    #编译安装python3.6.4
	cd /usr/local/src/
	wget https://www.python.org/ftp/python/3.6.4/Python-3.6.4.tar.xz
	tar xvf Python-3.6.4.tar.xz
	cd Python-3.6.4
	./configure && make && make install
	#建立Python环境,因为CentOS 6/7自带的是Python2,而Yum等工具依赖原来的Python,为了不扰乱原来的环境我们来使用Python3虚拟环境
	#cat >> /etc/profile << EOF
#PATH = \$PATH:/usr/local/src/Python-3.6.4/python
#EOF
	#替换原来python环境，会影响到yum等安装依赖
	#ln -sv /usr/local/bin/python3 /usr/bin/python
	
	#不替换Python默认环境，使用python3服务
	ln -sv /usr/local/bin/python3 /usr/bin/python3
	
	echo "-------Python3.6初始化安装完成-------"
}

#安装Kubernetes
function install_k8s() {
	#安装依赖
    yum -y install wget libselinux-python sqlite-devel xz gcc automake zlib-devel openssl-devel epel-release git
    #编译安装python3.6.4
	cd /usr/local/src/
	wget https://www.python.org/ftp/python/3.6.4/Python-3.6.4.tar.xz
	tar xvf Python-3.6.4.tar.xz
	cd Python-3.6.4
	./configure && make && make install
	#建立Python环境,因为CentOS 6/7自带的是Python2,而Yum等工具依赖原来的Python,为了不扰乱原来的环境我们来使用Python3虚拟环境
	cat >> /etc/profile << EOF
PATH = \$PATH:/usr/local/src/Python3.6.4/python
EOF
	ln -sv /usr/local/bin/python3 /usr/bin/python3
	echo "-------Python3.6初始化安装完成-------"
}


#所有的配置
#    hostname_config
#    firewall_config
#    yum_config
#    kernel_config
#    dns_config
#    user_add
#    install_jdk_and_tomcat
#    install_salt_minion
#    install_mysql
#    install_mongodb
#    install_docker
#    install_redis
#    install_python3
#    install_k8s



# 如果不指定参数，则执行默认功能模块
if [[ -z $* ]]; then
    firewall_config
    config_mirror_and_update
    kernel_config
    #dns_config
    install_jdk_and_tomcat
    install_salt_minion
fi

for arg in $* ; do
    case ${arg} in
    hostname)
    hostname_config
    ;;
	firewall)
    firewall_config
    ;;
    kernel)
    config_mirror_and_update
    kernel_config
    ;;
    user)
    user_add
    ;;
    dns)
    dns_config
    ;;
    java)
    install_jdk_and_tomcat
    ;;
    salt)
    install_salt_minion
    ;;
    zabbix)
    install_zabbix_agent
    ;;
    mysql)
    install_mysql_and_config
    ;;
    mongodb)
    install_mongodb
    ;;
    docker)
    install_docker
    ;;
	redis)
    install_redis
    ;;
	python3)
    install_python3
    ;;
	k8s)
    install_k8s
    ;;
    esac
done

cat << EOF
 +--------------------------------------------------------------+  
 |                === System init Finished ===                  |  
 +--------------------------------------------------------------+  
EOF
sleep 3
echo "Please reboot your system!"
