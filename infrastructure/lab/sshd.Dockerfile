# A Debian SSH server for the ADIS real-data lab: OpenSSH with PAM, logging through rsyslog,
# which forwards authentication logs (RFC 5424 over TCP) and the rest (RFC 3164 over UDP)
# to the lab agent. The "lab" account accepts only the lab client's key; it has no password.
FROM debian:12-slim
RUN apt-get update \
    && apt-get install -y --no-install-recommends openssh-server rsyslog bsdutils \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /run/sshd \
    && sed -i '/imklog/s/^/#/' /etc/rsyslog.conf \
    && useradd --create-home --shell /bin/bash lab \
    && usermod -p '*' lab
COPY sshd/adis-lab.conf /etc/ssh/sshd_config.d/adis-lab.conf
COPY sshd/forward.conf /etc/rsyslog.d/50-adis-forward.conf
COPY sshd/entrypoint.sh /entrypoint.sh
ENTRYPOINT ["/bin/sh", "/entrypoint.sh"]
