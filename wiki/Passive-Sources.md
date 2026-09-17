# Passive discovery sources

Subdomain discovery (`passive_enum`) asks subfinder's sources. Some need no key
and are always used: anubis, commoncrawl, crtsh, digitorus, hudsonrock,
rapiddns, scanmalware, shodanct, sitedossier, thc, threatcrowd, waybackarchive.
The rest are queried only when their key is set in `.env`, one per line with
nothing after the value — a trailing comment becomes part of the key. The
worker checks this list against what subfinder actually reads at start and
warns in its log if a source has been renamed, so a key is never silently
ignored.

The tables follow the order of `.env.example`. Each link is where the account
is created or the key is found.

## Certificate transparency and DNS history

| Variable | Service |
|---|---|
| `CERTSPOTTER_API_KEY` | https://sslmate.com/certspotter/ — key under your account |
| `DNSDB_API_KEY` | https://www.farsightsecurity.com/solutions/dnsdb/ (DomainTools); free community key at https://www.farsightsecurity.com/dnsdb-community-edition/ |
| `DNSDUMPSTER_API_KEY` | https://dnsdumpster.com/ — sign in, then the API page |
| `DNSREPO_API_KEY` | https://dnsrepo.noc.org/ |
| `MERKLEMAP_API_KEY` | https://www.merklemap.com/ — API keys in the dashboard |
| `SECURITYTRAILS_API_KEY` | https://securitytrails.com/app/account/credentials |
| `WHOISXMLAPI_API_KEY` | https://whoisxmlapi.com/ — My products → API key |

## Internet-wide scan indexes

Censys and FOFA take two parts; the worker joins them the way subfinder wants
(`ID:SECRET` and `EMAIL:KEY`). Set both halves or neither — half is ignored.

| Variable | Service |
|---|---|
| `CENSYS_API_ID` / `CENSYS_API_SECRET` | https://search.censys.io/account/api |
| `FOFA_EMAIL` / `FOFA_API_KEY` | https://en.fofa.info/ — personal center → API |
| `FULLHUNT_API_KEY` | https://fullhunt.io/ — settings → API |
| `NETLAS_API_KEY` | https://app.netlas.io/ — profile → API key |
| `ONYPHE_API_KEY` | https://www.onyphe.io/ — my account → API key |
| `QUAKE_API_KEY` | https://quake.360.net/ — personal center → API key |
| `SHODAN_API_KEY` | https://account.shodan.io/ |
| `ZOOMEYE_API_KEY` | https://www.zoomeye.org/ — profile → API key (subfinder calls this source `zoomeyeapi`) |

## Threat intelligence and reputation

| Variable | Service |
|---|---|
| `ALIENVAULT_API_KEY` | https://otx.alienvault.com/api — settings → OTX key |
| `LEAKIX_API_KEY` | https://leakix.net/ — account → API |
| `THREATBOOK_API_KEY` | https://x.threatbook.com/ — member center → API |
| `URLSCAN_API_KEY` | https://urlscan.io/user/profile/ |
| `VIRUSTOTAL_API_KEY` | https://www.virustotal.com/gui/my-apikey |

## Recon platforms and aggregators

Hackertarget, reconeer and submd work without a key and return more with one.
IntelX takes two parts, joined as `HOST:KEY`; the host is shown next to the key
and looks like `2.intelx.io`.

| Variable | Service |
|---|---|
| `BEVIGIL_API_KEY` | https://bevigil.com/osint-api |
| `BUFFEROVER_API_KEY` | https://tls.bufferover.run/ |
| `BUILTWITH_API_KEY` | https://api.builtwith.com/ |
| `C99_API_KEY` | https://api.c99.nl/ |
| `CHAOS_API_KEY` | https://cloud.projectdiscovery.io/ — ProjectDiscovery Cloud → API key |
| `CHINAZ_API_KEY` | https://apidatav2.chinaz.com/ |
| `DIGITALYAMA_API_KEY` | https://digitalyama.com/ |
| `DOMAINSPROJECT_API_KEY` | https://domainsproject.org/ |
| `DRIFTNET_API_KEY` | https://driftnet.io/ — account → API |
| `HACKERTARGET_API_KEY` | https://hackertarget.com/ — membership → API key |
| `INTELX_HOST` / `INTELX_API_KEY` | https://intelx.io/account?tab=developer |
| `PROFUNDIS_API_KEY` | https://profundis.io/ |
| `PUGRECON_API_KEY` | https://pugrecon.com/ |
| `RECONEER_API_KEY` | https://reconeer.com/ |
| `REDHUNTLABS_API_KEY` | https://redhuntlabs.com/ — attack surface recon API |
| `ROBTEX_API_KEY` | https://www.robtex.com/api/ |
| `RSECLOUD_API_KEY` | https://rsecloud.com/ |
| `SUBMD_API_KEY` | https://submd.io/ |
| `WINDVANE_API_KEY` | https://windvane.lptr.top/ |

## Code search

| Variable | Service |
|---|---|
| `GITHUB_TOKEN` | https://github.com/settings/tokens — a classic token with no scopes is enough |

## Checking what is configured

The worker logs the sources it has credentials for at start:

```
passive sources configured  count=3  sources="[censys github shodan]"
```

A variable set here but missing from that line was not read: check the spelling
against `.env.example`, and that nothing follows the value on its line.
