# **Tools** 

## **Subdomains** 

assetfinder (Find domains and subdomains potentially related to a given domain) 

<u>https://github.com/tomnomnom/assetfinder</u> 

```
assetfinder example.com
```

subfinder (getting subdomains from different services with API of that services) 

<u>https://github.com/projectdiscovery/subfinder</u> 

```
subfinder -d example.com -v -o example.com.txt
```

shuffledns (subdomain bruteforce) 

<u>https://github.com/projectdiscovery/shuffledns</u> 

Here are subdomain wordlists:

<u>https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt</u>

<u>https://wordlists-cdn.assetnote.io/data/automated/httparchive_subdomains_2026_02_27.txt</u>

```
shuffledns -d example.com -w subdomains-top1million-20000.txt -r
resolvers.txt -mode bruteforce -silent -o shuffle-example.com
```

dnsx (validate output subdomains) 

<u>https://github.com/projectdiscovery/dnsx</u> 

```
cat <gathered domains> | sort | uniq | dnsx -silent -o output/combined-
live.txt
```

gobuster (long term, using for Wildcard domain and virtual hosts bruteforce) 

<u>https://github.com/Oj/gobuster</u> 

```
gobuster dns -d example.com -w best-dns-wordlist.txt --wildcard -o gobuster-
example.com
```

## **Port Scanning** 

nmap 

<u>https://nmap.org/download.html</u> 

```
nmap -iL {filename} -A -p- -vvv -Pn --min-hostgroup 256 --min-rate 10000 --
max-retries 3 --defeat-rst-ratelimit --open -oA {scan-name}
```

(опціонально) naabu 

### <u>https://github.com/projectdiscovery/naabu</u> 

```
cat <список доменів, або ІР-адрес> | naabu -c 4 -rate 20 -top-ports 100 -
silent -o output/ports.txt
```

## **Web discovery** 

katana (краулер веб-додатків) 

### <u>https://github.com/projectdiscovery/katana</u> 

```
cat <список веб-додатків> | katana -d 5 -jsl -c 3 -p 3 -rl 10 -silent | tee
output/katana-example.com
```

urlfinder (пасивний пошук url-ів) 

### <u>https://github.com/projectdiscovery/urlfinder</u> 

```
cat <список веб-додатків> | urlfinder -silent | tee output/urlfinder-
example.com
```

httpx (сканер доступності веб-додатків) <u>https://github.com/projectdiscovery/httpx</u> 

```
cat <список веб-додатків, можливо з виводом утиліти katana та urlfinder> |
sort | uniq | httpx -title -sc -cl -location -fr -silent -delay 1s | tee
output/httpx-example.com
```

### httpx (функціонал скріншотів веб-додтаків) 

```
cat <список веб-додатків, можливо з виводом утиліти katana та urlfinder> |
sort | uniq | httpx -sc -title -tech-detect -screenshot -timeout 200 -
screenshot-timeout 200
```

**Vulnerability Scaner** 

nuclei 

### <u>https://github.com/projectdiscovery/nuclei</u> 

```
nuclei -l urls -o nuclei-default   -  скан по стандартним шаблонам
```

```
nuclei -l urls -t /root/nuclei-templates/http -o nuclei-http   -  скан по
кастомним шаблонам
```

## **Dirsearch** 

gobuster 

<u>https://github.com/Oj/gobuster</u> 

```
gobuster dir -u http://example.com -w wordlist -k -o dirs-example.com
```

```
інколи треба фільтрувати результати по розміру respons-а для уникнення
false-positive
```

```
gobuster dir -u https://example.com -w wordlist -k -o dirs-example.com --
exclude-length 503
```

