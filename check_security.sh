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

main(){
  U01
  U02
}

main $*