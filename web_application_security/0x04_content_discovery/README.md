# Content Discovery - WebSec 0x04
 
## Description
 
This project covers **content discovery** — the process of finding hidden resources on a web server that are not publicly advertised, such as directories, backup files, configuration files, admin panels, and forgotten endpoints.
 
> "What you don't know about your web application is exactly what attackers will find first."
 
---

## Target
 
| Field   | Value                        |
|---------|------------------------------|
| Machine | `cyber_websec_0x04`          |
| URL     | `http://web0x04.hbtn/`       |
 
---

## Tasks
 
### Task 0 — Manual Discovery: Secrets in Plain Sight
 
Uncover a hidden flag by thoroughly exploring the site's structure using manual discovery methods.
 
#### Step 1: robots.txt
 
```bash
curl http://web0x04.hbtn/robots.txt
```
 
- Look for `Disallow` entries pointing to hidden or restricted paths.

#### Step 2: sitemap.xml
 
```bash
curl http://web0x04.hbtn/sitemap.xml
```
 
- Sitemaps may expose routes not linked anywhere on the site.
- Find the unusual route — it contains the flag.

#### Step 3: favicon.ico
 
```bash
curl -s http://web0x04.hbtn/favicon.ico -o favicon.ico
md5sum favicon.ico
```
