#!/bin/bash
WORKDIR=$(dirname $(readlink -f $0))
cd $WORKDIR
pid_file=$WORKDIR/pid/pid_mtproxy
input_port=${1}
secret="${2}"
input_domain="${3}"
input_tag="${4}"
input_manage_port=8443
check_sys(){
    local checkType=$1
    local value=$2

    local release=''
    local systemPackage=''

    if [[ -f /etc/redhat-release ]]; then
        release="centos"
        systemPackage="yum"
    elif grep -Eqi "debian|raspbian" /etc/issue; then
        release="debian"
        systemPackage="apt"
    elif grep -Eqi "ubuntu" /etc/issue; then
        release="ubuntu"
        systemPackage="apt"
    elif grep -Eqi "centos|red hat|redhat" /etc/issue; then
        release="centos"
        systemPackage="yum"
    elif grep -Eqi "debian|raspbian" /proc/version; then
        release="debian"
        systemPackage="apt"
    elif grep -Eqi "ubuntu" /proc/version; then
        release="ubuntu"
        systemPackage="apt"
    elif grep -Eqi "centos|red hat|redhat" /proc/version; then
        release="centos"
        systemPackage="yum"
    fi

    if [[ "${checkType}" == "sysRelease" ]]; then
        if [ "${value}" == "${release}" ]; then
            return 0
        else
            return 1
        fi
    elif [[ "${checkType}" == "packageManager" ]]; then
        if [ "${value}" == "${systemPackage}" ]; then
            return 0
        else
            return 1
        fi
    fi
}

function pid_exists(){
  local exists=`ps aux | awk '{print $2}'| grep -w $1`
  if [[ ! $exists ]]
  then
    return 0;
  else
    return 1;
  fi
}

install(){
  cd $WORKDIR
  if [ ! -d "./pid" ];then
    mkdir "./pid"
  fi

  xxd_status=1
  echo a|xxd -ps &> /dev/null
  if [ $? != "0" ];then
    xxd_status=0
  fi

  if [[ "`uname -m`" != "x86_64" ]]; then
    if check_sys packageManager yum; then
      yum install -y openssl-devel zlib-devel iproute
      yum groupinstall -y "Development Tools"
      if [ $xxd_status == 0 ];then
        yum install -y vim-common
      fi
    elif check_sys packageManager apt; then
      apt-get -y update
      apt install -y git curl build-essential libssl-dev zlib1g-dev iproute2
      if [ $xxd_status == 0 ];then
        apt install -y vim-common
      fi
    fi 
  else
    if check_sys packageManager yum &&  [ $xxd_status == 0 ]; then
      yum install -y vim-common
    elif check_sys packageManager apt &&  [ $xxd_status == 0 ]; then
      apt-get -y update
      apt install -y vim-common
    fi
  fi

  if [[ "`uname -m`" != "x86_64" ]];then
    if [ ! -d 'MTProxy' ];then
      git clone https://github.com/TelegramMessenger/MTProxy
    fi;
    cd MTProxy
    make && cd objs/bin
    cp -f $WORKDIR/MTProxy/objs/bin/mtproto-proxy $WORKDIR
    cd $WORKDIR
  else
    wget https://github.com/ellermister/mtproxy/releases/download/0.02/mtproto-proxy -O mtproto-proxy -q
    chmod +x mtproto-proxy
  fi
}


print_line(){
  echo -e "========================================="
}


config_mtp(){
  cd $WORKDIR
   # config info
  public_ip=$(curl -s https://api.ip.sb/ip --ipv4)
  [ -z "$public_ip" ] && public_ip=$(curl -s ipinfo.io/ip --ipv4)
  #secret=$(head -c 16 /dev/urandom | xxd -ps)
  curl -s https://core.telegram.org/getProxySecret -o proxy-secret
  curl -s https://core.telegram.org/getProxyConfig -o proxy-multi.conf
  cat >./mtp_config <<EOF
#!/bin/bash
secret="${secret}"
port=${input_port}
web_port=${input_manage_port}
domain="${input_domain}"
proxy_tag="${input_tag}"
EOF
}

status_mtp(){
  if [ -f $pid_file ];then
    pid_exists `cat $pid_file`
    if [[ $? == 1 ]];then
      return 1
    fi
  fi
  return 0
}

info_mtp(){
  status_mtp
  if [ $? == 1 ];then
    source ./mtp_config
    public_ip=$(curl -s https://api.ip.sb/ip --ipv4)
    [ -z "$public_ip" ] && public_ip=$(curl -s ipinfo.io/ip --ipv4)
    domain_hex=$(xxd -pu <<< $domain | sed 's/0a//g')
    client_secret="ee${secret}${domain_hex}"
    echo -e "https://t.me/proxy?server=${public_ip}&port=${port}&secret=${client_secret}"
  else
    echo -e "Error."
  fi
}


run_mtp(){
  cd $WORKDIR
  status_mtp
  if [ $? == 1 ];then
    echo -e "提醒：\033[33mMTProxy已经运行，请勿重复运行!\033[0m"
  else
    curl -s https://core.telegram.org/getProxyConfig -o proxy-multi.conf
    source ./mtp_config
    nat_ip=$(echo $(ip a | grep inet | grep -v 127.0.0.1 | grep -v inet6 | awk '{print $2}' | cut -d "/" -f1 |awk 'NR==1 {print $1}'))
    public_ip=`curl -s https://api.ip.sb/ip --ipv4`
    [ -z "$public_ip" ] && public_ip=$(curl -s ipinfo.io/ip --ipv4)
    nat_info=""
    if [[ $nat_ip != $public_ip ]];then
      nat_info="--nat-info ${nat_ip}:${public_ip}"
    fi
    tag_arg=""
    [[ -n "$proxy_tag" ]] && tag_arg="-P $proxy_tag"
    ./mtproto-proxy -u nobody -p $web_port -H $port -S $secret --aes-pwd proxy-secret proxy-multi.conf -M 1 $tag_arg --domain $domain $nat_info >/dev/null 2>&1 &
    
    echo $!>$pid_file
    sleep 2
    info_mtp
  fi
}

debug_mtp(){
  cd $WORKDIR
  source ./mtp_config
  nat_ip=$(echo $(ip a | grep inet | grep -v 127.0.0.1 | grep -v inet6 | awk '{print $2}' | cut -d "/" -f1 |awk 'NR==1 {print $1}'))
  public_ip=`curl -s https://api.ip.sb/ip --ipv4`
  [ -z "$public_ip" ] && public_ip=$(curl -s ipinfo.io/ip --ipv4)
  nat_info=""
  if [[ $nat_ip != $public_ip ]];then
      nat_info="--nat-info ${nat_ip}:${public_ip}"
  fi
  tag_arg=""
  [[ -n "$proxy_tag" ]] && tag_arg="-P $proxy_tag"
  echo "当前正在运行调试模式："
  echo -e "\t你随时可以通过 Ctrl+C 进行取消操作"
  echo " ./mtproto-proxy -u nobody -p $web_port -H $port -S $secret --aes-pwd proxy-secret proxy-multi.conf -M 1 $tag_arg --domain $domain $nat_info"
  ./mtproto-proxy -u nobody -p $web_port -H $port -S $secret --aes-pwd proxy-secret proxy-multi.conf -M 1 $tag_arg --domain $domain $nat_info
}

stop_mtp(){
  local pid=`cat $pid_file`
  kill -9 $pid
  pid_exists $pid
  if [[ $pid == 1 ]]
  then
    echo "停止任务失败"
  fi
}

fix_mtp(){
  if [ `id -u` != 0 ];then
    echo -e "> ※ (该功能仅限 root 用户执行)"
  fi	

  print_line
  echo -e "> 开始清空防火墙规则/停止防火墙/卸载防火墙..."
  print_line

  if check_sys packageManager yum; then
    systemctl stop firewalld.service
    systemctl disable firewalld.service
    systemctl stop iptables
    systemctl disable iptables
    service stop iptables
    yum remove -y iptables
    yum remove -y firewalld
  elif check_sys packageManager apt; then
    iptables -F
    iptables -t nat -F
    iptables -P ACCEPT
    iptables -t nat -P ACCEPT
    service stop iptables
    apt-get remove -y iptables
    ufw disable
  fi
  
  print_line
  echo -e "> 开始安装/更新iproute2..."
  print_line
  
  if check_sys packageManager yum; then
    yum install -y epel-release
    yum update -y
	yum install -y iproute
  elif check_sys packageManager apt; then
    apt-get install -y epel-release
    apt-get update -y
	apt-get install -y iproute2
  fi
  
  echo -e "< 处理完毕，如有报错忽略即可..."
  echo -e "< 如遇到端口冲突，请自行关闭相关程序"
}



param=$1
if [[ "start" == $param ]];then
  echo "即将：启动脚本";
  run_mtp
elif  [[ "stop" == $param ]];then
  echo "即将：停止脚本";
  stop_mtp;
elif  [[ "debug" == $param ]];then
  echo "即将：调试运行";
  debug_mtp;
elif  [[ "restart" == $param ]];then
  stop_mtp
  run_mtp
elif  [[ "fix" == $param ]];then
  fix_mtp
else
  if [ ! -f "$WORKDIR/mtp_config" ] && [ ! -f "$WORKDIR/mtproto-proxy" ];then
    install
    config_mtp
    run_mtp
  else
    [ ! -f "$WORKDIR/mtp_config" ] && config_mtp
    echo "MTProxyTLS一键安装运行绿色脚本"
    print_line
    info_mtp
    print_line
    echo -e "脚本源码：https://github.com/ellermister/mtproxy"
    echo -e "配置文件: $WORKDIR/mtp_config"
    echo -e "卸载方式：直接删除当前目录下文件即可"
    echo "使用方式:"
    echo -e "\t启动服务 bash $0 start"
    echo -e "\t调试运行 bash $0 debug"
    echo -e "\t停止服务 bash $0 stop"
    echo -e "\t重启服务 bash $0 restart"
    echo -e "\t修复常见问题 bash $0 fix"
  fi
fi
