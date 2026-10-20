#!/usr/bin/env bash
# PID-scoped Linux audit rules: records which process sends kill/tgkill to uaRO.
# Run as root; does not send signals or attach to the game.
set -euo pipefail
mode=${1:-}; pid=${2:-}
if [[ ! $mode =~ ^(start|stop|report)$ || ! $pid =~ ^[1-9][0-9]*$ ]]; then
  echo "Usage: sudo $0 {start|stop|report} uaRO_PID" >&2; exit 2
fi
if (( EUID != 0 )); then echo 'Run as root (audit rules require CAP_AUDIT_CONTROL)' >&2; exit 1; fi
key="ro_stop_${pid}"
if [[ $mode == report ]]; then
  ausearch -k "$key" -i
  exit
fi
op=-a; [[ $mode == stop ]] && op=-d
for arch in b64 b32; do
  # kill(pid, signal): a0 = target PID; tgkill(tgid, tid, signal): a0 = process PID.
  for syscall in kill tgkill; do
    auditctl "$op" always,exit -F "arch=$arch" -S "$syscall" -F "a0=$pid" -k "$key"
  done
  # tkill(tid, signal) may target the main thread. Other TIDs need separate rules.
  auditctl "$op" always,exit -F "arch=$arch" -S tkill -F "a0=$pid" -k "$key"
done
printf '%s audit rules for PID %s (key %s)\n' "$mode" "$pid" "$key"
