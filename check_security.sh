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
main(){
  U01
  U02
  U03
  U04
  U05
  U06
  U07
  U08
  U09
  U10
}

main $*