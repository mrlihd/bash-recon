#!/bin/sh

# Requirements:
# - subfinder
# - assetfinder
# - ffuf
# - httprobe
# - gron
# - notify
# - dirsearch => create symlink
# - httpx
# - puredns,shuffledns
# - dnsvalidator

UNCOMMON_PORTS_WEB="81,300,591,593,832,981,1010,1311,1099,2082,2095,2096,2480,3000,3001,3002,3003,3128,3333,4243,4567,4711,4712,4993,5000,5104,5108,5280,5281,5601,5800,6543,7000,7001,7396,7474,8000,8001,8008,8014,8042,8060,8069,8080,8081,8083,8088,8090,8091,8095,8118,8123,8172,8181,8222,8243,8280,8281,8333,8337,8443,8500,8834,8880,8888,8983,9000,9001,9043,9060,9080,9090,9091,9092,9200,9443,9502,9800,9981,10000,10250,11371,12443,15672,16080,17778,18091,18092,20720,32000,55440,55672"
HEADER = "User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:72.0) Gecko/20100101 Firefox/72.0"
path='/home/kali/dev/bash/recon-project'
cd $path

if [ ! -d Recon ] 
then
    mkdir Recon
fi

cd Recon

domain=$1
# echo $domain

if [ ! -d $domain ] 
then
    mkdir $domain
fi

cd $domain

if [ -e all_subdomains.txt ]
then
    sort -u all_subdomains.txt -o all_subdomains.txt
fi

if [ ! -d .tmp ]
then
    mkdir .tmp
fi
cd .tmp

{
    # echo [+] Starting Subfinder:
    subfinder -all -silent -d $domain 
    # echo [+] Starting Assetfinder:
    assetfinder -subs-only $domain 
    # echo [+] Starting Puredns:
    puredns bruteforce $path/custom-wordlist.txt -r $path/resolvers.txt $domain -q
} > subs_pool.txt

# echo [+] Fuzzing with Ffuf:
# ffuf -s -w ../../temp-list.txt -u "http://FUZZ.$domain/" -o ffuf-subs.txt -H "User-Agent: Mozilla/5.0 (Windows; U; MSIE 9.0; WIndows NT 9.0; en-US))"
# ffuf -s -w ./custom-wordlist.txt -u "http://FUZZ.$domain/" -o ffuf-subs.txt -H "User-Agent: Mozilla/5.0 (Windows; U; MSIE 9.0; WIndows NT 9.0; en-US))"
# gron -m ffuf-subs.txt | grep host | grep -oE "\"[^\"]+\"" | cut -d"\"" -f2 >> subs_pool.txt

sort -u subs_pool.txt -o subs_pool.txt
# puredns resolve subs_pool.txt -w resolved-subdomains.txt -r $path/resolvers.txt -q
shuffledns -list subs_pool.txt -r $path/resolvers.txt -silent -o resolved-subdomains.txt
# rm subs_pool.txt
cat resolved-subdomains.txt |anew -q subs_pool.txt
cat subs_pool.txt |anew -q ../all_subdomains.txt

# if [ -e ../all_subdomains.txt ]
# then
# # echo $old
#     comm -13 ../all_subdomains.txt resolved-subdomains.txt > new-domains.txt
# else
#     cp resolved-subdomains.txt new-domains.txt
# fi

cat resolved-subdomains.txt |httprobe | anew -q all_webs_tmp.txt
httpx -l ../all_subdomains.txt -H $HEADER -p $UNCOMMON_PORTS_WEB -fhr -sc -threads 20 -retries 2 -timeout 20 -silent -td -title -o httpx.json -json
# httpx -l ../all_subdomains.txt -H $HEADER -p 8080,8443 -fhr -sc -threads 20 -retries 2 -timeout 20 -silent -td -title -o httpx.json -json -silent
cat httpx.json |gron -s |grep url |cut -d "\"" -f4 |anew -q all_webs_tmp.txt
cat all_webs_tmp.txt |anew ../all_webs.txt > ../new_webs.txt

cd ..
if [ -s new_webs.txt ]
then
    notify -data new_webs.txt -silent
    nuclei -l new_webs.txt -retries 2 -timeout 10 -silent -fhr -json -o new_webs_nuclei.json -r $path/resolvers.txt | anew -q all_webs_nuclei.json
    # dirsearch -l new_webs.txt -o dirsearch-res.html --format=html -r -R 1 -e aspx,php,jsp,txt,rar,zip,json,html,sql -x 404,500-599 -q
fi