# Xarex Pentest Lab

Spin up a local stack of intentionally vulnerable services to test every Xarex scanner module.

## Quick Start

```bash
cd probe/testlab
docker-compose up -d
```

Then run the integration tests:

```bash
cd probe
go test ./... -run TestXarexLab -v -timeout 5m -tags integration
```

Stop and clean up:

```bash
docker-compose down -v
```

## Services

| Container | Port | Severity | What it tests |
|---|---|---|---|
| redis-noauth | 6379 | CRITICAL | Unauthenticated Redis access → RCE via config rewrite |
| mongo-noauth | 27017 | CRITICAL | Unauthenticated MongoDB → full DB read/write |
| elasticsearch-noauth | 9200 | CRITICAL | Unauthenticated Elasticsearch → all indices exposed |
| ftp-anon | 21 | HIGH | FTP anonymous login |
| memcached-exposed | 11211 | HIGH | Memcached with no auth + DDoS amplification |
| smtp-openrelay | 25 | HIGH | SMTP open relay → spam/phishing abuse |
| nginx-oldtls | 8443 | MEDIUM | TLS 1.0/1.1, 3DES SWEET32, no HSTS |
| nginx-baseline | 8080 | INFO | Clean HTTP service for fingerprinting |
