#!/bin/sh
# Start rsyslog and sshd once the lab client's public key exists.
set -e
waited=0
while [ ! -s /keys/lab.pub ] && [ "$waited" -lt 120 ]; do
  sleep 1
  waited=$((waited + 1))
done
install -d -m 700 -o lab -g lab /home/lab/.ssh
install -m 600 -o lab -g lab /keys/lab.pub /home/lab/.ssh/authorized_keys
ssh-keygen -A >/dev/null
rsyslogd
logger -p user.notice -t adis-lab "ssh server ready"
exec /usr/sbin/sshd -D
