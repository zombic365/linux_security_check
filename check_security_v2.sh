#!/bin/bash

source /root/linux_security_check/common_script.cfg
source /root/linux_security_check/common_color.cfg

if [ -f /root/check_report.log ]; then
  rm -f /root/check_report.log
fi


U30(){
  REPORT_LOG "M" "U30" "Sendmail version check."
  RUNC "which sendmail"
  if [ ${res} -eq 1 ]; then    
    REPORT_LOG "W" "SMTP not installed."
    U31 "1"
  else
    U31 "0"
  fi
}

U31(){
  REPORT_LOG "M" "U31" "Restrictions on spam mail relay."
  check_status=$1
  if [ ${check_status} == "1" ]; then
    REPORT_LOG "W" "SMTP not installed."
    U32 "1"
  elif [ ${check_status} == "0" ]; then
    echo "ok"
    U32 "0"
  fi
}

U32(){
  REPORT_LOG "M" "U32" "Prevention of Sendmail execution by general users."
  check_status=$1
  if [ ${check_status} == "1" ]; then
    REPORT_LOG "W" "SMTP not installed."
  elif [ ${check_status} == "0" ]; then
    echo "ok"
 fi
}

U33(){
  REPORT_LOG "M" "U33" "DNS security version patch."
  RUNC "U32" "which named"

  if [ ${check_status} == "1" ]; then
    REPORT_LOG "W" "BIND not installed."
    U34 "1"
  elif [ ${check_status} == "0" ]; then
    echo "ok"
    U34 "0"
  fi
}

U34(){
  REPORT_LOG "M" "U34" "DNS zone transfer settings."
  check_status=$1
  if [ ${check_status} == "1" ]; then
    REPORT_LOG "W" "BIND not installed."
  elif [ ${check_status} == "0" ]; then
    echo "ok"
  fi
}

U35(){
  REPORT_LOG "M" "U35" "Remove web service directory listing."
  RUNC "grep -R 'Options Indexes FollowSymLinks' /etc/httpd/conf/httpd.conf"

  if [ ${res} -eq 0 ]; then
    REPORT_LOG "N" "grep -R 'Options Indexes FollowSymLinks' /etc/httpd/conf/httpd.conf" "[Options Indexes FollowSymLinks] Settings" 
  elif [ ${res} -eq 1 ]; then
    REPORT_LOG "Y" "grep -R 'Options Indexes FollowSymLinks' /etc/httpd/conf/httpd.conf"
  fi  
}

U36(){
  REPORT_LOG "M" "U36" "Web Services Web Process Authority Limitation."
  RUNC "ps -ef |grep apache |grep -v 'auto' |awk '{print $1}' |uniq"

  if [ ${res} -eq 0 ]; then
    service_name=$(ps -ef |grep apache |grep -v 'auto' |awk '{print $1}' |uniq)
    service_login=$(grep apache /etc/passwd |awk -F':' '{print $7}')
    if [ ${service_name} != "root" -a ${service_login} == "/sbin/nologin" ]; then
      RUNC "grep -E 'User ${service_name}' /etc/httpd/conf/httpd.conf"
      if [ ${res} -eq 0 ]; then
        RUNC "grep -E 'Group ${service_name}' /etc/httpd/conf/httpd.conf"
        if [ ${res} -eq 0 ]; then
          REPORT_LOG "Y" "U36" "grep -E '^User ${service_name}|^Group ${service_name}' /etc/httpd/conf/httpd.conf"
        else
          REPORT_LOG "N" "U36" "grep -E '^User ${service_name}|^Group ${service_name}' /etc/httpd/conf/httpd.conf" "[Http service user, group] root."
        fi
      else
        REPORT_LOG "N" "U36" "grep -E '^User ${service_name}|^Group ${service_name}' /etc/httpd/conf/httpd.conf" "[Http service user] root."
      fi
    else
      REPORT_LOG "N" "U36" "grep -E '^User ${service_name}|^Group ${service_name}' /etc/httpd/conf/httpd.conf" "http service user, group root OR http service user, group ${service_name} root uid."
    fi
  elif  [ ${res} -eq 1 ]; then
    REPORT_LOG "W" "U36" "grep -E '^User ${service_name}|^Group ${service_name}' /etc/httpd/conf/httpd.conf" "HTTP not installed."
  fi
}

U37(){
  REPORT_LOG "M" "U37" "Access to the web service parent directory is prohibited."
  RUNC "grep -E 'AllowOverrid None' /etc/httpd/conf/httpd.conf"

  if [ ${res} -eq 1 ]; then 
    REPORT_LOG "Y" "U37" "grep -E 'AllowOverrid None' /etc/httpd/conf/httpd.conf"
  elif [ $[res} -eq 0 ]; then
    REPORT_LOG "N" "U37" "grep -E 'AllowOverrid None' /etc/httpd/conf/httpd.conf" "[AllowOverride None] option setting."
  fi
}

U38(){
  REPORT_LOG "M" "U38" "Remove unnecessary files for web services."
  RUNC "find /etc/httpd/ -type d -name manual >/dev/null"

  if [ ${res} -eq 1 ]; then 
    REPORT_LOG "Y" "U38" "find /etc/httpd/ -type d -name manual"
  elif [ $[res} -eq 0 ]; then
    check_dir=$(find /etc/httpd/ -type d -name manual)
    if [ -z  ${check_dir} ]; then
      REPORT_LOG "Y" "U38" "find /etc/httpd/ -type d -name manual"
    else
      REPORT_LOG "N" "U38" "find /etc/httpd/ -type d -name manual" "Not list dir."
    fi
  fi
}

U39(){
  REPORT_LOG "M" "U39" "Do not use web service links."
  RUNC "grep 'Options Indexes FollowSymLinks' /etc/httpd/conf/httpd.conf"

  if [ ${res} -eq 1 ]; then 
    REPORT_LOG "Y" "U39" "grep 'Options Indexes FollowSymLinks' /etc/httpd/conf/httpd.conf"
  elif [ $[res} -eq 0 ]; then
      REPORT_LOG "N" "U39" "grep 'Options Indexes FollowSymLinks' /etc/httpd/conf/httpd.conf" "[Options Indexes FollowSymLinks] option setting"
  fi
}

main(){
  # SERVICE_MGMT=("U19" "U20" "U21" "U22" "U23" "U24" "U25" "U26" "U27" "U28" "U29" "U30" "U31" "U32" "U33" "U34" "U35" "U36" "U37" "U38" "U39" "U40" "U41" "U60" "U61" "U62" "U63" "U64" "U65" "U66" "U67" "U68" "U69" "U70" "U71")
  SERVICE_MGMT=("U30" "U31" "U32" "U33" "U34" "U35" "U36" "U37" "U38" "U39")  
  for i in ${SERVICE_MGMT[@]}; do
    echo "==================================================================================" >>/root/check_report.log
    ${i}
  done
  echo -e "${Color_Off}Completed" >>/root/check_report.log
}

main $*