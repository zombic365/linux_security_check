#!/bin/bash
source ./common_script.cfg
source ./common.color.cfg

#U-01(상)
U01(){
  RUNC "grep -n "/lib/security/pam_securetty.so" /etc/pam.d/login |cut -d: -f1"
  if [ "${res}" == 0 ]; then
    RUNC "echo -e "${Check_No} ${BOLD}[U01] 'grep -n "/lib/security/pam_securetty.so" /etc/pam.d/login |cut -d: -f1'${Color_off}""
  else
    RUNC "echo -e "${Check_Yes} ${BOLD}[U01] 'grep -n "/lib/security/pam_securetty.so" /etc/pam.d/login |cut -d: -f1'${Color_off}""
  fi

  RUNC "find /etc -type f -name "securetty""
  if [ "${res}" == 0 ]; then
    RUNC "grep "pts" /etc/securetty"
    if [ "${res}" == 0 ]; then
      RUNC "echo -e "${Check_Yes} ${BOLD}[U01] 'grep "pts" /etc/securetty'""
    else
      RUNC "echo -e "${Check_No} ${BOLD}[U01] 'grep "pts" /etc/securetty'""
    fi
  fi
  RUNC "grep -i "PermitRootLogin yes" /etc/ssh/sshd_config"
  if [ "${res}" == 0 ]; then
    RUNC "echo -e "${Check_No} ${BOLD}[U01] 'grep -i "PermitRootLogin yes" /etc/ssh/sshd_config'${Color_off}""
  else
    RUNC "echo -e "${Check_Yes} ${BOLD}[U01] 'grep -i "PermitRootLogin yes" /etc/ssh/sshd_config'${Color_off}""
  fi
}

main(){
  U01
}

main $*