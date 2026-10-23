# bpftrace for the ADIS real-data lab (infrastructure/lab/compose.yaml).
# The container runs privileged in the lab only, to trace the Docker VM's kernel.
FROM alpine:3.20
RUN apk add --no-cache bpftrace
ENTRYPOINT []
