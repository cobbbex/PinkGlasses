-- +goose Up
-- +goose StatementBegin
CREATE TABLE domain (
    id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    scope_id    uuid NOT NULL REFERENCES scope(id) ON DELETE CASCADE,
    name        text NOT NULL,
    apex        text NOT NULL,
    is_wildcard boolean NOT NULL DEFAULT false,
    sources     text[] NOT NULL DEFAULT '{}',
    first_seen  timestamptz NOT NULL DEFAULT now(),
    last_seen   timestamptz NOT NULL DEFAULT now(),
    UNIQUE (scope_id, name)
);

CREATE TABLE dns_record (
    id         uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    domain_id  uuid NOT NULL REFERENCES domain(id) ON DELETE CASCADE,
    rtype      text NOT NULL,
    value      text NOT NULL,
    ttl        int,
    first_seen timestamptz NOT NULL DEFAULT now(),
    last_seen  timestamptz NOT NULL DEFAULT now(),
    UNIQUE (domain_id, rtype, value)
);

CREATE TABLE ip_address (
    id         uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    scope_id   uuid NOT NULL REFERENCES scope(id) ON DELETE CASCADE,
    addr       inet NOT NULL,
    ptr        text,
    asn        int,
    as_org     text,
    country    text,
    cloud      text,
    is_shared  boolean NOT NULL DEFAULT false,
    first_seen timestamptz NOT NULL DEFAULT now(),
    last_seen  timestamptz NOT NULL DEFAULT now(),
    UNIQUE (scope_id, addr)
);

CREATE TABLE domain_ip (
    domain_id  uuid REFERENCES domain(id) ON DELETE CASCADE,
    ip_id      uuid REFERENCES ip_address(id) ON DELETE CASCADE,
    via        text NOT NULL,
    first_seen timestamptz NOT NULL DEFAULT now(),
    last_seen  timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (domain_id, ip_id, via)
);

CREATE TABLE service (
    id         uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    ip_id      uuid NOT NULL REFERENCES ip_address(id) ON DELETE CASCADE,
    port       int NOT NULL,
    proto      text NOT NULL DEFAULT 'tcp',
    last_state text NOT NULL DEFAULT 'open',
    first_seen timestamptz NOT NULL DEFAULT now(),
    last_seen  timestamptz NOT NULL DEFAULT now(),
    UNIQUE (ip_id, port, proto)
);

CREATE TABLE service_observation (
    id             uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    service_id     uuid NOT NULL REFERENCES service(id) ON DELETE CASCADE,
    run_id         uuid NOT NULL REFERENCES scan_run(id) ON DELETE CASCADE,
    worker_id      uuid REFERENCES worker(id) ON DELETE SET NULL,
    observed_at    timestamptz NOT NULL DEFAULT now(),
    banner         text,
    product        text,
    version        text,
    http           jsonb,
    tls            jsonb,
    screenshot_key text,
    raw_key        text,
    UNIQUE (service_id, run_id)
);

CREATE TABLE certificate (
    id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    sha256      bytea NOT NULL UNIQUE,
    subject_cn  text,
    issuer      text,
    sans        text[] NOT NULL DEFAULT '{}',
    not_before  timestamptz,
    not_after   timestamptz,
    self_signed boolean
);

CREATE TABLE technology (
    service_id uuid REFERENCES service(id) ON DELETE CASCADE,
    name       text NOT NULL,
    version    text NOT NULL DEFAULT '',
    cpe        text,
    confidence int,
    first_seen timestamptz NOT NULL DEFAULT now(),
    last_seen  timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (service_id, name, version)
);

CREATE TABLE finding (
    id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    scope_id    uuid NOT NULL REFERENCES scope(id) ON DELETE CASCADE,
    asset_kind  text NOT NULL,
    asset_id    uuid NOT NULL,
    kind        text NOT NULL,
    severity    text NOT NULL DEFAULT 'info',
    title       text NOT NULL,
    evidence    jsonb NOT NULL DEFAULT '{}',
    status      text NOT NULL DEFAULT 'open',
    first_seen  timestamptz NOT NULL DEFAULT now(),
    last_seen   timestamptz NOT NULL DEFAULT now(),
    resolved_at timestamptz
);

CREATE TABLE change_event (
    id            uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    run_id        uuid NOT NULL REFERENCES scan_run(id) ON DELETE CASCADE,
    run_target_id uuid REFERENCES run_target(id) ON DELETE SET NULL,
    scope_id      uuid NOT NULL REFERENCES scope(id) ON DELETE CASCADE,
    kind          text NOT NULL,
    asset_kind    text NOT NULL,
    asset_id      uuid NOT NULL,
    before        jsonb,
    after         jsonb,
    created_at    timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE audit_log (
    id         bigserial PRIMARY KEY,
    actor      text,
    action     text NOT NULL,
    subject    text,
    detail     jsonb NOT NULL DEFAULT '{}',
    created_at timestamptz NOT NULL DEFAULT now()
);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS audit_log;
DROP TABLE IF EXISTS change_event;
DROP TABLE IF EXISTS finding;
DROP TABLE IF EXISTS technology;
DROP TABLE IF EXISTS certificate;
DROP TABLE IF EXISTS service_observation;
DROP TABLE IF EXISTS service;
DROP TABLE IF EXISTS domain_ip;
DROP TABLE IF EXISTS ip_address;
DROP TABLE IF EXISTS dns_record;
DROP TABLE IF EXISTS domain;
-- +goose StatementEnd
