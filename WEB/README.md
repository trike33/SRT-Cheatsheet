```
python3 domains-to-httpx.py target_assets.json | httpx -title -tech-detect -sc -cl -fr -o httpx_out

python3 domains-to-httpx.py target_assets.json | katana -o katana_out -jc

python3 domain-parser.py target_assets.json >> scope

for line in $(cat scope);do grep $line katana_out;done >> crawl_scope

httpx -l crawl_scope -sc -cl -fr -o crawl_results

grep 200 crawl_results | grep js >> valid_js

nuclei -t /home/AMBERJACK/vfea0rousv/nuclei-templates/http/exposures/ -l valid_js -no-mhe -ni
```
