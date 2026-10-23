#!/bin/sh
# Real outbound traffic of this lab container only: DNS lookups, HTTPS page requests and a
# ping, repeated for DURATION seconds. Nothing is scanned and no other host is targeted.
set -u
SITES="example.com www.wikipedia.org api.github.com www.cloudflare.com www.python.org"
end=$(( $(date +%s) + ${DURATION:-150} ))
sleep 5
while [ "$(date +%s)" -lt "$end" ]; do
  for site in $SITES; do
    nslookup "$site" >/dev/null 2>&1 || true
    curl -s -o /dev/null --max-time 10 "https://$site/" || true
  done
  ping -c 1 -W 2 1.1.1.1 >/dev/null 2>&1 || true
  sleep 5
done

# Stay up a little longer than the capture and flow exporter, which share this namespace.
sleep 20
