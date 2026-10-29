# Fingerprint lab

`internal/fingerprint` names Citrix NetScaler, Atlassian Confluence and Jira,
Zammad, Zimbra, Microsoft Exchange and Kerio Connect. There are two ways to
check it, and neither sends anything to anyone else's server.

## 1. Offline, against what search engines already recorded

Shodan, Censys and FOFA keep the front page of every web server they see.
Export a few hundred per product, plus a sample of unrelated web servers, and
let `fpcheck` say how many the rules name:

```sh
# Shodan (shodan CLI; the download is gzipped JSON lines)
shodan download --limit 500 exchange 'http.title:"Outlook" "X-OWA-Version"'
shodan download --limit 500 netscaler 'http.title:"NetScaler Gateway"'
shodan download --limit 500 random 'http.status:200 port:443'

# Censys (censys CLI, v2 search: a JSON array of hosts)
censys search 'services.http.response.html_title: "Zimbra Web Client Sign In"' --pages 3 -o zimbra.json

# FOFA (API; say which fields the export holds)
curl "https://fofa.info/api/v1/search/all?key=$FOFA_KEY&size=500&fields=ip,port,host,title,header,body&qbase64=$(printf 'app="Atlassian-Confluence"' | base64 -w0)" > confluence.json

go run ./tools/fpcheck \
  exchange.json.gz=exchange netscaler.json.gz=netscaler \
  zimbra.json=zimbra random.json.gz=none
go run ./tools/fpcheck -fofa-fields ip,port,host,title,header,body confluence.json=confluence
```

Each export gets a report: how many banners the rules named as the expected
product, how many with a version, every product named, and a list of misses
(or, for `=none`, false positives) to read. A miss is either a rule to add or
a banner that is not the product at all; search queries are loose.

`-fixtures internal/fingerprint/testdata` writes matched banners as test cases
(misses go to `testdata/misses/`, which the tests do not read). They carry no
address, but a page can still name its owner: read and trim one before you
commit it.

Shodan follows redirects and Censys records the response to `/`, so neither
shows what the follow-up probes (`/owa/auth/logon.aspx`, `/rest/api/2/serverInfo`,
…) would return. That is what the lab is for.

## 2. Live, against instances you run

```sh
docker compose -f deploy/fplab/docker-compose.yml --profile zammad up -d     # :28081
docker compose -f deploy/fplab/docker-compose.yml --profile atlassian up -d  # :28090, :28085 (4 GB+ RAM)
docker compose -f deploy/fplab/docker-compose.yml --profile php up -d        # :28082, PHP signals and an error page
go run ./tools/fpcheck -lab http://127.0.0.1:28081
```

`-lab` prints each request the worker would make, what each response showed,
and the merged result. It refuses any address that is not loopback or
private: real targets are scanned through the pipeline, against a scope that
was authorized.

Confluence and Jira start in their setup wizard, which does not look like a
production front page. Finish setup with a free 30-day trial licence from
my.atlassian.com first.

The rest have no maintained container image and run as VMs on a host-only or
NAT network:

| Product | How to get it |
|---|---|
| Zimbra | Zimbra 10 (Daffodil) open-source build or the 8.8.15 FOSS installer on Ubuntu 20.04/22.04, 8 GB RAM |
| Microsoft Exchange | Windows Server 2022 evaluation + Exchange Server SE (or 2019 CU15) in a lab AD domain, 16 GB RAM |
| Kerio Connect | 30-day trial, Linux .deb or Windows installer |
| Citrix NetScaler | NetScaler VPX Express / trial image for KVM, VMware or Hyper-V; configure a Gateway vserver, and a SAML action against any IdP (Keycloak in a container will do) to see the SAML redirect |

Point `fpcheck -lab` at the VM's private address.

To run the whole pipeline against the lab instead, set
`ASM_ALLOW_PRIVATE_TARGETS=true` (as `deploy/e2e` does) and add the lab
addresses to a company of their own.
