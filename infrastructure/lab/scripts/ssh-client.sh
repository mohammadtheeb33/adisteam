#!/bin/sh
# Lab-only SSH scenarios against the lab SSH server (172.31.250.40), without any password:
# key-based logins of the "lab" account, attempts for an account that does not exist, and an
# unknown key for an existing account. Each produces real sshd and PAM syslog messages.
set -u
[ -f /keys/lab ] || ssh-keygen -q -t ed25519 -N "" -C adis-lab -f /keys/lab
[ -f /root/unknown ] || ssh-keygen -q -t ed25519 -N "" -C unknown -f /root/unknown
OPTS="-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o BatchMode=yes -o ConnectTimeout=5"
sleep 20
for round in 1 2 3; do
  ssh $OPTS -i /keys/lab lab@172.31.250.40 'id; uptime; sleep 3' >/dev/null 2>&1 || true
  ssh $OPTS -i /root/unknown nosuchuser@172.31.250.40 true >/dev/null 2>&1 || true
  ssh $OPTS -i /root/unknown lab@172.31.250.40 true >/dev/null 2>&1 || true
  sleep 5
done
ssh $OPTS -i /keys/lab lab@172.31.250.40 'sleep 20' >/dev/null 2>&1 || true
echo "ssh scenarios done"
