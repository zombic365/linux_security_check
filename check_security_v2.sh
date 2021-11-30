#!/bin/bash
source /root/linux_security_check/common_script.cfg
source /root/linux_security_check/common_color.cfg

if [ -f /root/check_report.log ]; then
  rm -f /root/check_report.log
fi

U30(){
  # REPORT_LOG "M" "U30" "Sendmail version check."
  CMD="which sendmail"
  RUNC "${CMD}"
  if [ ${res} -eq 1 ]; then
    REPORT_LOG "C" "${FUNCNAME}" "SMTP not installed."
  elif [ ${res} -eq 0 ]; then
    echo "ok"
  fi
}

U31(){
  # REPORT_LOG "M" "U31" "Restrictions on spam mail relay."
  CMD="which sendmail"
  RUNC "${CMD}"
  if [ ${res} -eq 1 ]; then
    REPORT_LOG "C"  "${FUNCNAME}" "SMTP not installed."
  elif [ ${res} -eq 0 ]; then
    echo "ok"
  fi
}

U32(){
  # REPORT_LOG "M" "U32" "Prevention of Sendmail execution by general users."
  CMD="which sendmail"
  RUNC "${CMD}"
  if [ ${res} -eq 1 ]; then
    REPORT_LOG "C" "${FUNCNAME}" "SMTP not installed."
  elif [ ${res} -eq 0 ]; then
    echo "ok"
  fi
}

U33(){
  # REPORT_LOG "M" "U33" "DNS security version patch."
  CMD="which sendmail"
  RUNC "${CMD}"
  if [ ${res} -eq 1 ]; then
    REPORT_LOG "C" "${FUNCNAME}" "SMTP not installed."
  elif [ ${res} -eq 0 ]; then
    echo "ok"
  fi
}

U34(){
  # REPORT_LOG "M" "U34" "DNS zone transfer settings."
  CMD="which sendmail"
  RUNC "${CMD}"
  if [ ${res} -eq 1 ]; then
    REPORT_LOG "C" "${FUNCNAME}" "SMTP not installed."
  elif [ ${res} -eq 0 ]; then
    echo "ok"
  fi
}

U35(){
  # REPORT_LOG "M" "U35" "Remove web service directory listing."
  CMD="grep -R 'Options Indexes FollowSymLinks' /etc/httpd/conf/httpd.conf"
  RUNC "${CMD}"

  if [ ${res} -eq 0 ]; then
    REPORT_LOG "N" "${FUNCNAME}" "${CMD}" "[Options Indexes FollowSymLinks] Settings" 
  elif [ ${res} -eq 1 ]; then
    REPORT_LOG "Y" "${FUNCNAME}" "${CMD}"
  fi  
}

U36(){
  # REPORT_LOG "M" "U36" "Web Services Web Process Authority Limitation."
  CMD="ps -ef |grep apache |grep -v 'auto' |awk '{print $1}' |uniq"
  RUNC "${CMD}"

  if [ ${res} -eq 0 ]; then
    service_name=$(ps -ef |grep apache |grep -v 'auto' |awk '{print $1}' |uniq)
    service_login=$(grep apache /etc/passwd |awk -F':' '{print $7}')
    CMD="grep -E '^User ${service_name}|^Group ${service_name}' /etc/httpd/conf/httpd.conf"
    if [ "${service_name}" != root -a "${service_login}" == /sbin/nologin ]; then
      RUNC "grep -E 'User ${service_name}' /etc/httpd/conf/httpd.conf"
      if [ ${res} -eq 0 ]; then
        RUNC "grep -E 'Group ${service_name}' /etc/httpd/conf/httpd.conf"
        if [ ${res} -eq 0 ]; then
          REPORT_LOG "Y" "${FUNCNAME}" "${CMD}"
        else
          REPORT_LOG "N" "${FUNCNAME}" "${CMD}" "[Http service user, group] root."
        fi
      else
        REPORT_LOG "N" "${FUNCNAME}" "${CMD}" "[Http service user] root."
      fi
    else
      REPORT_LOG "N" "${FUNCNAME}" "${CMD}" "http service user, group root OR http service user, group ${service_name} root uid."
    fi
  elif  [ ${res} -eq 1 ]; then
    REPORT_LOG "C" "${FUNCNAME}" "${CMD}" "HTTP not installed."
  fi
}

U37(){
  # REPORT_LOG "M" "U37" "Access to the web service parent directory is prohibited."
  CMD="grep -E 'AllowOverrid None' /etc/httpd/conf/httpd.conf"
  RUNC "${CMD}"
  
  if [ ${res} -eq 1 ]; then 
    REPORT_LOG "Y" "${FUNCNAME}" "${CMD}"
  elif [ ${res} -eq 0 ]; then
    REPORT_LOG "N" "${FUNCNAME}" "${CMD}" "[AllowOverride None] option setting."
  fi
}

U38(){
  # REPORT_LOG "M" "U38" "Remove unnecessary files for web services."
  CMD="find /etc/httpd/ -type d -name manual"
  RUNC "${CMD}"

  if [ ${res} -eq 1 ]; then 
    REPORT_LOG "Y" "${FUNCNAME}" "${CMD}"
  elif [ ${res} -eq 0 ]; then
    check_dir=$(find /etc/httpd/ -type d -name manual)
    if [ -z  ${check_dir} ]; then
      REPORT_LOG "Y" "${FUNCNAME}" "${CMD}"
    else
      REPORT_LOG "N" "${FUNCNAME}" "${CMD}" "Not list dir."
    fi
  fi
}

U39(){
  # REPORT_LOG "M" "U39" "Do not use web service links."
  CMD="grep 'Options Indexes FollowSymLinks' /etc/httpd/conf/httpd.conf"
  RUNC "${CMD}"

  if [ ${res} -eq 1 ]; then 
    REPORT_LOG "Y" "${FUNCNAME}" "${CMD}"
  elif [ ${res} -eq 0 ]; then
      REPORT_LOG "N" "${FUNCNAME}" "${CMD}" "[Options Indexes FollowSymLinks] option setting"
  fi
}

main(){
  # SERVICE_MGMT=("U19" "U20" "U21" "U22" "U23" "U24" "U25" "U26" "U27" "U28" "U29" "U30" "U31" "U32" "U33" "U34" "U35" "U36" "U37" "U38" "U39" "U40" "U41" "U60" "U61" "U62" "U63" "U64" "U65" "U66" "U67" "U68" "U69" "U70" "U71")
  SERVICE_MGMT=("U30" "U31" "U32" "U33" "U34" "U35" "U36" "U37" "U38" "U39")  
  for i in ${SERVICE_MGMT[@]}; do
    echo "==================================================================================" >>/root/check_report.log
    ${i}
    REPORT_LOG "M" "test"
  done
  echo -e "${Color_Off}Completed" >>/root/check_report.log
}

main $*