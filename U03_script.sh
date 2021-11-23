#!/bin/bash

auth required /lib/security/pam_tally.so deny=5 unlock_time=120 no_magic_root
account required /lib/security/pam_tally.so no_magic_root reset

# no_magic_root root에게는 패스워드 잠금 설정을 적용하지 않음
# deny=5 5회 입력 실패 시 패스워드 잠금
# unlock_time 게정 잠김 후 마지막 계정 실패 시간 부터 설정 된 시간이 지나면 자동 계정 잠김 해제(초)
# reset  접속 시도 성공 시 실패 횟수 초기화