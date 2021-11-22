#!/bin/bash
source ./common_script.cfg
source ./common.color.cfg

#U-01(상)
U01(){
  RUNC "grep -n "/lib/security/pam_securetty.so" /etc/pam.d/login |cut -d: -f1"
  if [ "${res}" == 0 ]; then
    line_num=$(grep -n "/lib/security/pam_securetty.so" /etc/pam.d/login |cut -d: -f1)
    RUNC "sed -i '${line_num}s/.*/#&/g' /etc/pam.d/login"
  fi
  RUNC "find /etc -type f -name "securetty""
  if [ "${res}" == 0 ]; then
    RUNC "grep "pts" /etc/securetty"
    if [ "${res}" == 0 ]; then
      RUNC "sed -i 's/pts/#&/g' /etc/securetty"
    fi
  fi
  RUNC "grep -i "PermitRootLogin yes" /etc/ssh/sshd_config"
  if [ "${res}" == 0 ]; then
    RUNC "echo "[CHECK] [U01] []

main(){
  U01
}

main $*