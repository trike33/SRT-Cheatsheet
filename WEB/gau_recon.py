import requests
import sys
import json
from pwn import *
import time
import threading
import traceback
import argparse
from urllib.parse import urlparse

#stop_threads = False

def update_progress_bar(progress_bar, start_time):
    global stop_threads
    while True:
        if stop_threads:
            break
        else:
            elapsed_seconds = int(time.time() - start_time)
            hours = elapsed_seconds // 3600
            minutes = (elapsed_seconds % 3600) // 60
            seconds = elapsed_seconds % 60
            progress_bar.status(f"Time waiting: {hours:02}:{minutes:02}:{seconds:02}")
            time.sleep(1)  # Update every second

def waybackurls(host, with_subs, progress_bar):
    global stop_threads
    if with_subs:
        url = 'http://web.archive.org/cdx/search/cdx?url=*.%s/*&output=json&fl=original&collapse=urlkey' % host
    else:
        url = 'http://web.archive.org/cdx/search/cdx?url=%s/*&output=json&fl=original&collapse=urlkey' % host
    
    # Start the progress bar in a separate thread
    start_time = time.time()
    progress_thread = threading.Thread(target=update_progress_bar, args=(progress_bar, start_time))
    progress_thread.start()
    #print("thread started")
    
    try:
        #print("try entered")
        r = requests.get(url)
        print("[+] urls gathered sucessfully!")
        stop_threads = True
        progress_thread.join()
        progress_bar.success()
    except:
        stop_threads = True
        progress_thread.join()
        traceback.print_exc()
    results = r.json()
    return results[1:] 

def save_output(filename, results):
    """
    Function used to save results into a file
    """
    
    with open(filename, 'a') as file:
        for result in results:
            result = result[0] + "\n"
            file.write(result)

    print(f"Successfully saved {len(results)} (duplicate) results into {filename}!")
    return

def ext_check(filename):
    """
    Function used to check for sensitive extensions
    """

    global sens_extensions
    results = set()
    with open(filename, 'r') as file:
        lines = file.readlines()

        for line in lines:
            line = line.rstrip()
            path = urlparse(line).path
            extension = '.' + path.split('.')[-1] if '.' in path else ''

            if extension in sens_extensions:
                results.add(line)
                
    for result in results:
        print(result)

    return

def param_check(filename):
    """
    Checks for known vulnerable params
    """
    global open_redirect
    global sqli
    global xss
    global lfi
    global rce
    global ssrf

    or_out = set()
    sqli_out = set()
    xss_out = set()
    lfi_out = set()
    rce_out = set()
    ssrf_out = set()

    with open(filename, 'r') as file:
        lines = file.readlines()

        for line in lines:
            line = line.rstrip()

            if any(item in line for item in open_redirect):
                or_out.add(line)

            if any(item in line for item in sqli):
                sqli.add(line)

            if any(item in line for item in xss):
                xss.add(line)

            if any(item in line for item in lfi):
                lfi.add(line)

            if any(item in line for item in rce):
                rce.add(line)

            if any(item in line for item in ssrf):
                ssrf.add(line)

    print(f"\nOpen redirect: {", ".join(map(str, or_out))}")
    print(f"\nSQLi: {", ".join(map(str, sqli_out))}")
    print(f"\nXSS: {", ".join(map(str, xss_out))}")
    print(f"\nLFI: {", ".join(map(str, lfi_out))}")
    print(f"\nRCE: {", ".join(map(str, rce_out))}")
    print(f"\nSSRF: {", ".join(map(str, ssrf_out))}")

    return

def check_handler(output, check_extension, check_params):

    iteration = 0
    while iteration < 1:
        iteration += 1
        if output:
            if check_extension and check_params:
                ext_check(output)
                param_check(output)

            elif check_extension and not check_params:
                ext_check(output)

            elif not check_extension and check_params:
                param_check(output)

            else:
                print("Extension check: disabled")
                print("Params check: disabled")

        else:
            print("Check is only allowed with the output flag!")

    return


if __name__ == '__main__':

    #Global vars
    open_redirect = {"?next=","?url=","?target=","?rurl=","?dest=","?destination=","?redir=","?redirect_uri=","?redirect_url=","?redirect=","/redirect/","/cgi-bin/redirect.cgi?","/out/","/out?","?view=","/login?to=","?image_url=","?go=","?return=","?returnTo=","?return_to=","?checkout_url=","?continue=","?return_path="}
    sqli = {"?id=","?page=","?dir=","?search=","?category=","?file=","?class=","?url=","?news=","?item=","?menu=","?lang=","?name=","?ref=","?title=","?view=","?topic=","?thread=","?type=","?date=","?form=","?join=","?main=","?nav=","?region="}
    xss = {"?q=","?s=","?search=","?id=","?lang=","?keyword=","?query=","?page=","?keywords=","?year=","?view=","?email=","?type=","?name=","?p=","?month=","?image=","?list_type=","?url=","?terms=","?categoryid=","?key=","?login=","?begindate=","?enddate="}
    lfi = {"?cat=","?dir=","?action=","?board=","?date=","?detail=","?file=","?download=","?path=","?folder=","?prefix=","?include=","?page=","?inc=","?locate=","?show=","?doc=","?site=","?type=","?view=","?content=","?document=","?layout=","?mod=","?conf="}
    rce = {"?cmd=","?exec=","?command=","?execute=","?ping=","?query=","?jump=","?code=","?reg=","?do=","?func=","?arg=","?option=","?load=","?process=","?step=","?read=","?function=","?req=","?feature=","?exe=","?module=","?payload=","?run=","?print="}
    ssrf = {"?dest=","?redirect=","?uri=","?path=","?continue=","?url=","?window=","?next=","?data=","?reference=","?site=","?html=","?val=","?validate=","?domain=","?callback=","?return=","?page=","?feed=","?host=","?port=","?to=","?out=","?view=","?dir="}
    sens_extensions = {
        '.xls', '.xml', '.xlsx', '.json', '.pdf', '.sql', '.doc', '.docx', '.pptx', '.txt', '.zip', 
        '.tar.gz', '.tgz', '.bak', '.7z', '.rar', '.log', '.cache', '.secret', '.db', '.backup', '.yml',
        '.gz', '.config', '.csv', '.yaml', '.md', '.md5', '.tar', '.xz', '.7zip', '.p12', '.pem', '.key',
        '.crt', '.csr', '.sh', '.pl', '.py', '.java', '.class', '.jar', '.war', '.ear', '.sqlitedb',
        '.sqlite3', '.dbf', '.db3', '.accdb', '.mdb', '.sqlcipher', '.gitignore', '.env', '.ini', '.conf',
        '.properties', '.plist', '.cfg'}

    #initialize parser
    parser = argparse.ArgumentParser(description="Gau argument parser")
    group = parser.add_mutually_exclusive_group(required=True)

    #add arguments
    group.add_argument("-d", "--domain",type=str, help="Target domain")
    group.add_argument("-f", "--file", type=str, help="File containing the target domains")
    parser.add_argument("-sub", "--enable-subdomains", action="store_true", help="Enable subdomains collection")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose mode")
    parser.add_argument("-o", "--output", type=str, help="Filename of output file")
    parser.add_argument("-ce", "--check-extension", action="store_true", help="Enable sensitive extensions check(it will get the results from the output file)")
    parser.add_argument("-cp", "--check-params", action="store_true", help="Enable top 25 known vulnerable params check(it will get the results from the output file)")

    #parse arguments
    args = parser.parse_args()

    #logic for the arguments
    if args.domain:
        host = args.domain
        stop_threads = False
        progress_bar = log.progress(f"Collecting URLs for host {host}...")
        urls = waybackurls(host, args.enable_subdomains, progress_bar)
        #print(f'[+]Found {len(urls)} URLs!')

        if args.output and not args.verbose:
            save_output(args.output, urls)

        elif not args.output and args.verbose:
            for url in urls:
                print(url)

        elif args.output and args.verbose:
            for url in urls:
                print(url)
            save_output(args.output, urls)

        else:
            print("there was an error with the supplied args, please check them")
            sys.exit(1)

        check_handler(args.output, args.check_extension, args.check_params)
        print("program ended its execution!")


    elif args.file:
        hosts = set()

        #read file containing target domains
        with open(args.file, 'r') as file:
            lines = file.readlines()

            for line in lines:
                line = line.rstrip()
                hosts.add(line)

        #handle each domain individually
        for host in hosts:
            stop_threads = False
            progress_bar = log.progress(f"Collecting URLs for host {host}...")
            urls = waybackurls(host, args.enable_subdomains, progress_bar)
            #print(f'[+]Found {len(urls)} URLs!')

            if args.output and not args.verbose:
                save_output(args.output, urls)

            elif not args.output and args.verbose:
                for url in urls:
                    print(url)

            elif args.output and args.verbose:
                for url in urls:
                    print(url)
                save_output(args.output, urls)

            else:
                print("there was an error with the supplied args, please check them")
                sys.exit(1)

        check_handler(args.output, args.check_extension, args.check_params)

        print("program ended its execution!")
    
    else:
        print("A problem occurred with the arguments you supplied")
        sys.exit(1)
