# Traffic, capture, flow-export and SSH-client tools for the ADIS real-data lab.
FROM alpine:3.20
RUN apk add --no-cache curl bind-tools tcpdump softflowd openssh-client
COPY scripts/ /opt/lab/
ENTRYPOINT []
