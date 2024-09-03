```
python3 domains-to-httpx.py target_assets.json | httpx -title -tech-detect -sc -cl -fr -o httpx_out

python3 domain-parser.py target_assets.json

python3 domains-to-httpx.py target_assets.json | katana -o katana_out -jc

httpx -l katana_out -sc -cl -fr -o crawl_results
```
