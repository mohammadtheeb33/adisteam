BEGIN;

CREATE SCHEMA IF NOT EXISTS adis;

CREATE TABLE adis.alembic_version (
    version_num VARCHAR(32) NOT NULL,
    CONSTRAINT alembic_version_pkc PRIMARY KEY (version_num)
);

-- Running upgrade  -> 23e849fe26bd

CREATE TABLE adis.agents (
    id UUID DEFAULT gen_random_uuid() NOT NULL,
    name VARCHAR(255) NOT NULL,
    hostname VARCHAR(255) NOT NULL,
    os_type VARCHAR(32) NOT NULL,
    agent_version VARCHAR(64) NOT NULL,
    status VARCHAR(32) DEFAULT 'pending' NOT NULL,
    first_seen TIMESTAMP WITH TIME ZONE,
    last_seen TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT now() NOT NULL,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT now() NOT NULL,
    CONSTRAINT pk_agents PRIMARY KEY (id),
    CONSTRAINT ck_agents_seen_order CHECK (first_seen IS NULL OR last_seen IS NULL OR last_seen >= first_seen),
    CONSTRAINT ck_agents_os_type CHECK (os_type IN ('linux', 'windows', 'macos', 'other')),
    CONSTRAINT ck_agents_status CHECK (status IN ('pending', 'active', 'inactive', 'decommissioned'))
);

CREATE TABLE adis.security_events (
    id UUID DEFAULT gen_random_uuid() NOT NULL,
    event_id UUID NOT NULL,
    timestamp TIMESTAMP WITH TIME ZONE NOT NULL,
    received_at TIMESTAMP WITH TIME ZONE NOT NULL,
    event_type VARCHAR(128) NOT NULL,
    source_type VARCHAR(64) NOT NULL,
    source_name VARCHAR(256) NOT NULL,
    agent_id UUID,
    host_id VARCHAR(255),
    severity_hint VARCHAR(16),
    src_ip INET,
    dst_ip INET,
    src_port INTEGER,
    dst_port INTEGER,
    protocol VARCHAR(16),
    payload JSONB NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT now() NOT NULL,
    CONSTRAINT pk_security_events PRIMARY KEY (id),
    CONSTRAINT uq_security_events_event_id UNIQUE (event_id),
    CONSTRAINT fk_security_events_agent_id_agents FOREIGN KEY(agent_id) REFERENCES adis.agents (id) ON DELETE SET NULL,
    CONSTRAINT ck_security_events_src_port_range CHECK (src_port IS NULL OR src_port BETWEEN 0 AND 65535),
    CONSTRAINT ck_security_events_dst_port_range CHECK (dst_port IS NULL OR dst_port BETWEEN 0 AND 65535)
);

CREATE INDEX ix_security_events_timestamp ON adis.security_events (timestamp);

CREATE INDEX ix_security_events_received_at_brin ON adis.security_events USING brin (received_at);

CREATE INDEX ix_security_events_event_type_timestamp ON adis.security_events (event_type, timestamp);

CREATE INDEX ix_security_events_host_id_timestamp ON adis.security_events (host_id, timestamp) WHERE host_id IS NOT NULL;

CREATE INDEX ix_security_events_agent_id_timestamp ON adis.security_events (agent_id, timestamp) WHERE agent_id IS NOT NULL;

CREATE INDEX ix_security_events_src_ip ON adis.security_events (src_ip) WHERE src_ip IS NOT NULL;

CREATE INDEX ix_security_events_dst_ip ON adis.security_events (dst_ip) WHERE dst_ip IS NOT NULL;

ALTER TABLE adis.agents ENABLE ROW LEVEL SECURITY;

ALTER TABLE adis.security_events ENABLE ROW LEVEL SECURITY;

INSERT INTO adis.alembic_version (version_num) VALUES ('23e849fe26bd') RETURNING adis.alembic_version.version_num;

-- Running upgrade 23e849fe26bd -> 5b8e2c4f1a93

ALTER TABLE adis.alembic_version ENABLE ROW LEVEL SECURITY;

UPDATE adis.alembic_version SET version_num='5b8e2c4f1a93' WHERE adis.alembic_version.version_num = '23e849fe26bd';

COMMIT;
