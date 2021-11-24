#!/bin/bash
source /root/linux_security_check/common_script.cfg
source /root/linux_security_check/common_color.cfg

if [ -f /root/check_report.log ]; then 
  rm -f /root/check_report.log
fi

#U-01(상)
U01(){
  RUNC "grep -n '/lib/security/pam_securetty.so' /etc/pam.d/login |cut -d: -f1"
  if [ "${res}" == 0 ]; then
    REPORT_LOG "N" "01" "grep -n '/lib/security/pam_securetty.so' /etc/pam.d/login |cut -d: -f1"
  else
    REPORT_LOG "Y" "01" "grep -n '/lib/security/pam_securetty.so' /etc/pam.d/login |cut -d: -f1"
  fi

  RUNC "grep 'pts' /etc/securetty"
  if [ "${res}" == 0 ]; then
    REPORT_LOG "N" "01" "grep 'pts' /etc/securetty"
  elif [ "${res}" == 2 ]; then
    REPORT_LOG "W" "01" "grep 'pts' /etc/securetty" "Not found file"
  else
    REPORT_LOG "Y" "01" "grep 'pts' /etc/securetty"
  fi

  RUNC "grep -i 'PermitRootLogin yes' /etc/ssh/sshd_config"
  if [ "${res}" == 0 ]; then
    REPORT_LOG "N" "01" "grep -i 'PermitRootLogin yes' /etc/ssh/sshd_config"
  else
    REPORT_LOG "Y" "01" "grep -i 'PermitRootLogin yes' /etc/ssh/sshd_config"
  fi
}

U02(){
# RUNC grep -E 'retry|minlen|lcredit|ucredit|dcredit|ocredit' /etc/security/pwquality.conf
  RUNC "grep 'retry' /etc/security/pwquality.conf |cut -d= -f2 |tr -d ' '"
  if [ "${res}" == 0 ]; then
    pwa_value=`expr $(grep 'retry' /etc/security/pwquality.conf |cut -d= -f2 |tr -d ' ') + 0`
    if [ ${pwa_value} -eq 3 ]; then
      REPORT_LOG "Y" "02" "grep 'retry' /etc/security/pwquality.conf |cut -d= -f2 |tr -d ' '"
    else 
      REPORT_LOG "N" "02" "grep 'retry' /etc/security/pwquality.conf |cut -d= -f2 |tr -d ' '"
    fi
  elif [ "${res}" == 1 ]; then
    REPORT_LOG "W" "02" "grep 'retry' /etc/security/pwquality.conf |cut -d= -f2 |tr -d ' '" "Not found optioon"
  fi

  RUNC "grep 'minlen' /etc/security/pwquality.conf |cut -d= -f2 |tr -d ' '"
  if [ "${res}" == 0 ]; then
    pwa_value=`expr $(grep 'minlen' /etc/security/pwquality.conf |cut -d= -f2 |tr -d ' ') + 0`
    if [[ "${pwa_value}" -eq "-1" ]]; then
      REPORT_LOG "Y" "02" "grep 'minlen' /etc/security/pwquality.conf |cut -d= -f2 |tr -d ' '"
    else 
      REPORT_LOG "N" "02" "grep 'minlen' /etc/security/pwquality.conf |cut -d= -f2 |tr -d ' '"
    fi
  elif [ "${res}" == 1 ]; then
    REPORT_LOG "W" "02" "grep 'minlen' /etc/security/pwquality.conf |cut -d= -f2 |tr -d ' '" "Not found optioon"
  fi

  RUNC "grep 'lcredit' /etc/security/pwquality.conf |cut -d= -f2 |tr -d ' '"
  if [ "${res}" == 0 ]; then
    pwa_value=`expr $(grep 'lcredit' /etc/security/pwquality.conf |cut -d= -f2 |tr -d ' ') + 0`
    if [[ "${pwa_value}" -eq "-1" ]]; then
      REPORT_LOG "Y" "02" "grep 'lcredit' /etc/security/pwquality.conf |cut -d= -f2 |tr -d ' '"
    else 
    REPORT_LOG "N" "02" "grep 'lcredit' /etc/security/pwquality.conf |cut -d= -f2 |tr -d ' '"
  fi
  elif [ "${res}" == 1 ]; then
    REPORT_LOG "W" "02" "grep 'lcredit' /etc/security/pwquality.conf |cut -d= -f2 |tr -d ' '" "Not found optioon"
  fi

  RUNC "grep 'ucredit' /etc/security/pwquality.conf |cut -d= -f2 |tr -d ' '"
  if [ "${res}" == 0 ]; then
    pwa_value=`expr $(grep 'ucredit' /etc/security/pwquality.conf |cut -d= -f2 |tr -d ' ') + 0`
    if [[ "${pwa_value}" -eq "-1" ]]; then
      REPORT_LOG "Y" "02" "grep 'ucredit' /etc/security/pwquality.conf |cut -d= -f2 |tr -d ' '"
    else 
      REPORT_LOG "N" "02" "grep 'ucredit' /etc/security/pwquality.conf |cut -d= -f2 |tr -d ' '"
    fi
  elif [ "${res}" == 1 ]; then
    REPORT_LOG "W" "02" "grep 'ucredit' /etc/security/pwquality.conf |cut -d= -f2 |tr -d ' '" "Not found optioon"
  fi

  RUNC "grep 'dcredit' /etc/security/pwquality.conf |cut -d= -f2 |tr -d ' '"
  if [ "${res}" == 0 ]; then
    pwa_value=`expr $(grep 'dcredit' /etc/security/pwquality.conf |cut -d= -f2 |tr -d ' ') + 0`
    if [[ "${pwa_value}" -eq "-1" ]]; then
      REPORT_LOG "Y" "02" "grep 'dcredit' /etc/security/pwquality.conf |cut -d= -f2 |tr -d ' '"
    else 
      REPORT_LOG "N" "02" "grep 'dcredit' /etc/security/pwquality.conf |cut -d= -f2 |tr -d ' '"
    fi
  elif [ "${res}" == 1 ]; then
    REPORT_LOG "W" "02" "grep 'dcredit' /etc/security/pwquality.conf |cut -d= -f2 |tr -d ' '" "Not found optioon"
  fi

  RUNC "grep 'ocredit' /etc/security/pwquality.conf |cut -d= -f2 |tr -d ' '"
  if [ "${res}" == 0 ]; then
    pwa_value=`expr $(grep 'ocredit' /etc/security/pwquality.conf |cut -d= -f2 |tr -d ' ') + 0`
    if [[ "${pwa_value}" -eq "-1" ]]; then
      REPORT_LOG "Y" "02" "grep 'ocredit' /etc/security/pwquality.conf |cut -d= -f2 |tr -d ' '" 
    else 
      REPORT_LOG "N" "02" "grep 'ocredit' /etc/security/pwquality.conf |cut -d= -f2 |tr -d ' '"
    fi
  elif [ "${res}" == 1 ]; then
    REPORT_LOG "W" "02" "grep 'ocredit' /etc/security/pwquality.conf |cut -d= -f2 |tr -d ' '" "Not found optioon"
  fi
}

U03(){
  RUNC "ls -l /lib/security/pam_tally.so"
  if [ "${res}" == 0 ]; then
    RUNC "grep 'pam_tally.so' /etc/pam.d/system-auth"
    if [ "${res}" == 1 ]; then
      REPORT_LOG "N" "03" "grep 'pam_tally.so' /etc/pam.d/system-auth"
    fi
  elif [ "${res}" == 2 ]; then
    REPORT_LOG "W" "03" "ls -l /lib/security/pam_tally.so" "Not found file"
  fi
}

U04(){
  if [ -f /etc/passwd -a -f /etc/shadow ]; then
    REPORT_LOG "Y" "04" "ls -l /etc/passwd && ls -l /etc/shadow"
  else
    REPORT_LOG "N" "04" "ls -l /etc/passwd && ls -l /etc/shadow"
  fi
}

U05(){
  RUNC "echo ${PATH} |grep -E '::|\.:|\.\.|\.'"

  if [ "${res}" == 1 ]; then
    REPORT_LOG "Y" "05" "echo ${PATH} |grep -E '::|\.:|\.\.|\.'"
  else
    REPORT_LOG "N" "05" "echo ${PATH} |grep -E '::|\.:|\.\.|\.'"
  fi

  case ${SHELL} in
    "/bin/bash" )
      RUNC "grep -E '::|\.:|\.\.' /etc/profile"

      if [ "${res}" == 1 ]; then
        REPORT_LOG "Y" "05" "grep -E '::|\.:|\.\.' /etc/profile"
      else
        REPORT_LOG "N" "05" "grep -E '::|\.:|\.\.' /etc/profile"
      fi

      RUNC "grep -E '::|\.:|\.\.' $HOME/.bash_profile"
      if [ "${res}" == 1 ]; then
        REPORT_LOG "Y" "05" "grep -E '::|\.:|\.\.' $HOME/.bash_profile"
      else
        REPORT_LOG "N" "05" "grep -E '::|\.:|\.\.' $HOME/.bash_profile"
      fi
    ;;
  esac
}

U06(){
  check_nouser=$(find / -nouser -print 2>/dev/null)
  if [ -n ${check_nouse} ]; then
    REPORT_LOG "N" "06" "find / -nouser -print 2>/dev/null"
  else
    REPORT_LOG "Y" "06" "find / -nouser -print 2>/dev/null"
  fi
  check_nogroup=$(find / -nogroup -print 2>/dev/null)
  if [ -n ${check_nogroup} ]; then
    REPORT_LOG "N" "06" "find / -nogroup -print 2>/dev/null"
  else
    REPORT_LOG "Y" "06" "find / -nogroup -print 2>/dev/null"
  fi
}

U07(){
  check_user=$(stat -c '%U' /etc/passwd)
  check_group=$(stat -c '%G' /etc/passwd)
  check_permission=$(stat -c '%a' /etc/passwd)
  if [ ${check_user} == root -a ${check_group} == root -a "${check_permission}" == 644 ]; then
    REPORT_LOG "N" "07" "stat -c '%U %G %a' /etc/passwd"
  else
    REPORT_LOG "Y" "07" "stat -c '%U %G %a' /etc/passwd"
  fi
}

U08(){
  check_user=$(stat -c '%U' /etc/shadow)
  check_group=$(stat -c '%G' /etc/shadow)
  check_permission=$(stat -c '%a' /etc/shadow)
  if [ ${check_user} == root -a ${check_group} == root -a "${check_permission}" == 400 ]; then
    REPORT_LOG "N" "08" "stat -c '%U %G %a' /etc/shadow"
  else
    REPORT_LOG "Y" "08" "stat -c '%U %G %a' /etc/shadow"
  fi
}

U09(){
  check_user=$(stat -c '%U' /etc/hosts)
  check_group=$(stat -c '%G' /etc/hosts)
  check_permission=$(stat -c '%a' /etc/hosts)
  if [ ${check_user} == root -a ${check_group} == root -a "${check_permission}" == 600 ]; then
    REPORT_LOG "N" "09" "stat -c '%U %G %a' /etc/hosts"
  else
    REPORT_LOG "Y" "09" "stat -c '%U %G %a' /etc/hosts"
  fi
}

U10(){
  RUNC "stat -c '%U %G %a' /etc/xinetd.conf"
  if [ "${res}" == 0 ]; then
    check_user=$(stat -c '%U' /etc/xinetd.conf)
    check_group=$(stat -c '%G' /etc/xinetd.conf)
    check_permission=$(stat -c '%a' /etc/xinetd.conf)
    if [ ${check_user} == root -a ${check_group} == root -a "${check_permission}" == 600 ]; then
      REPORT_LOG "N" "10" "stat -c '%U %G %a' /etc/xinetd.conf"
    else
      REPORT_LOG "Y" "10" "stat -c '%U %G %a' /etc/xinetd.conf"
    fi
  elif [ "${res}" == 1 ]; then
    REPORT_LOG "W" "10" "stat -c '%U %G %a' /etc/xinetd.conf" "Not found file."
  fi
}

U44(){
  check_uid=$(awk -F':' '{print $3}' /etc/passwd |grep -c  '^0')

  if [ ${check_uid} -eq 1 ]; then
    REPORT_LOG "Y" "44" "awk -F':' '{print $3}' /etc/passwd |grep -c  '^0'"
  else
    REPORT_LOG "N" "44" "awk -F':' '{print $3}' /etc/passwd |grep -c '^0'" " Result > 1"
  fi
}

U45(){  
  check_permission=$(stat -c '%a' /usr/bin/su)
  if [ "${check_permission}" == 4750 ]; then
    REPORT_LOG "Y" "45" "stat -c '%a' /usr/bin/su"
  else
    REPORT_LOG "N" "45" "stat -c '%a' /usr/bin/su" "Result != 4750"
  fi

  check_group=$(stat -c '%G' /usr/bin/su)
  if [ "${check_group}" == root ]; then
    REPORT_LOG "N" "45" "stat -c '%G' /usr/bin/su" "Result != wheel"
  elif [ "${check_group}" == wheel ]; then
    REPORT_LOG "Y" "45" "stat -c '%G' /usr/bin/su"
  fi

  check_su_user=$(awk -F':' '/^wheel/ {print $4}' /etc/group |wc -l)
  if [ "${check_su_user}" -eq 0 ]; then
    REPORT_LOG "Y" "45" "awk -F':' '/^wheel/ {print $4}' /etc/group |wc -l"
  else
    REPORT_LOG "W" "45" "awk -F':' '/^wheel/ {print $4}' /etc/group |wc -l" "Result > 0"
  fi
  # grep "pam_rootok.so" /etc/pam.d/su |grep -v "^#" |wc -l
  # grep "pam_wheel.so" /etc/pam.d/su |grep -v "^#" |wc -
  # PAM작업 해야함
}

U46(){
  check_pass_min=$(awk '/^PASS_MIN_LEN/ {print $2}' /etc/login.defs)
  if [ ${check_pass_min} -gt 7 ]; then
    REPORT_LOG "Y" "46" "awk '/^PASS_MIN_LEN/ {print $2}' /etc/login.defs"
  else
    REPORT_LOG "N" "46" "awk '/^PASS_MIN_LEN/ {print $2}' /etc/login.defs" "Result < 7"
  fi
}

U47(){
  check_pass_min=$(awk '/^PASS_MAX_DAYS/ {print $2}' /etc/login.defs)
  if [ ${check_pass_min} -lt 91 ]; then
    REPORT_LOG "Y" "47" "awk '/^PASS_MAX_DAYS/ {print $2}' /etc/login.defs"
  else
    REPORT_LOG "N" "47" "awk '/^PASS_MAX_DAYS/ {print $2}' /etc/login.defs" "Result < 91"
  fi
}

U48(){
  check_pass_min=$(awk '/^PASS_MIN_DAYS/ {print $2}' /etc/login.defs)
  if [ ${check_pass_min} -gt 0 ]; then
    REPORT_LOG "Y" "48" "awk '/^PASS_MIN_DAYS/ {print $2}' /etc/login.defs"
  else
    REPORT_LOG "N" "48" "awk '/^PASS_MIN_DAYS/ {print $2}' /etc/login.defs" "Result < 0"
  fi
}

U49(){
  #불필요 계정 확인하는 절차
  REPORT_LOG "C" "49" "check please file."
}

U50(){
  check_group_null=$(awk -F':' '/^root/ {print $4}' /etc/group)
  if [ "$(awk -F':' '/^root/ {print $4}' /etc/group)" == " " ]; then
    REPORT_LOG "Y" "50" "awk -F':' '/^root/ {print $4}' /etc/group"
  else
    REPORT_LOG "N" "50" "awk -F':' '/^root/ {print $4}' /etc/group" "root group not null."
  fi
}

U51(){
  REPORT_LOG "C" "51" "check please file."
}

U52(){
  check_uid_null=$(awk -F':' '{print $3}' /etc/passwd |uniq -d)
  if [ -z ${check_uid_null} ]; then
    REPORT_LOG "Y" "52" "awk -F':' '{print $3}' /etc/passwd |uniq -d"
  elif [ ! -z ${check_uid_null} ]; then
    REPORT_LOG "N" "52" "awk -F':' '{print $3}' /etc/passwd |uniq -d" "Overlap uid."
  fi
}

U53(){
  REPORT_LOG "C" "53" "check please file."
}

main(){
  ACCOUNT_MGMT=("U01" "U02" "U03" "U04" "U44" "U45" "U46" "U47" "U48" "U49" "U50" "U51" "U52" "U53")

  for i in ${ACCOUNT_MGMT[@]}; do
    echo "==================================================================================" >>/root/check_report.log
    ${i}
  done
}

main $*