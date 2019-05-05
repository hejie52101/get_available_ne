# -*- coding: utf-8 -*-
import paramiko
import os
import time
import sys
import traceback
import re
import threading
import pymysql
from bs4 import BeautifulSoup as bs
# logging.basicConfig(filename='transfer_file.log', filemode='w', level=logging.WARNING, format='%(asctime)s - %(levelname)s - %(message)s')
# logger = logging.getLogger("logger")

ne_info_list = []
ne_excluded_dict = {}
hardware_list = []

def wait_end(chan, timeout = 30):
    start_time = time.time()
    result = ""
    while True:
        if re.findall(r">", result[-5:]):
            break
        elif time.time() - start_time > timeout:
            result = ""
            break
        else:
            time.sleep(0.3)
            if chan.recv_ready():
                result += chan.recv(9999999).decode(errors='ignore')
    return chan, result

class my_thread(threading.Thread):
    def __init__(self,func,args,name="my_thread"):
        threading.Thread.__init__(self)
        self.name = name
        self.func = func
        self.args = args
        self.exitcode = 0
        self.exception = None
        self.exc_traceback = ''
    def run(self):
        try:
            self.func(*self.args)
        except Exception as e:
            self.exitcode = 1
            self.exc_traceback = ''.join(traceback.format_exception(*sys.exc_info()))

def search_ne(flag):
    print("%s: start to search all NEs..." % threading.current_thread().name)
    sys.stdout.flush()
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh.connect("172.18.98.199", 22, "root", "eci_root")
    stdin, stdout, stderr = ssh.exec_command("nmap -sn 200.200." + flag + ".0/24 -n")
    ne_list = re.findall(r"200\.200\."+flag+r"\.\d+", stdout.read().decode(errors='ignore'))
    ssh.close()
    try:
        for ip in ne_list:
            locals()["g_" + ip] = my_thread(func=get_ne_status, args=(ip,), name="g_"+ip)
            locals()["g_" + ip].start()
        for ip in ne_list:
            locals()["g_"+ip].join()
        for ip in ne_list:
            if locals()["g_"+ip].exitcode == 1:
                raise Exception(locals()["g_"+ip].exc_traceback)
    except Exception as e:
        raise e

def get_ne_status(ip):
    print("%s: start to login %s..." % (threading.current_thread().name, ip))
    sys.stdout.flush()
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        ssh.connect(ip, 22, "admin", "admin1")
    except Exception as e:
        try:
            ssh.connect(ip, 22, "admin", "admin1")
        except Exception as e:
            prefix = '.'.join(ip.split(".")[:3])+".0/24"
            if prefix in ne_excluded_dict:
                ne_excluded_dict[prefix].append(ip)
            else:
                ne_excluded_dict[prefix] = [ip]
            return
    chan = ssh.invoke_shell()
    time.sleep(1)
    chan.recv(9999999).decode(errors='ignore')
    chan.send("\nshow version|no-more\n")
    chan, version_rst = wait_end(chan)
    chan.send("\nshow system status|no-more\n")
    chan, sys_status  = wait_end(chan)
    chan.send("\nshow chassis hardware detail | except 'Card Mac Addr|Vendor' | no-more\n")
    chan, hardware_rst = wait_end(chan)
    ssh.close()
    if version_rst:
        version = re.findall(r"Software Release.*: (\S+)", version_rst)[0]
    else:
        version = "NA"
    if sys_status:
        run_time, dswp_status, cfpal_status, system_status = re.findall(r"Run time.*: (.*)\r\n.*DSWP Status.*: (\w+).*\n.*CFPAL.*: (\w+).*\n.*Operational Status.*: (\w+)", sys_status)[0]
    else:
        run_time=dswp_status=cfpal_status=system_status = "NA"
    if hardware_rst:
        hardware = re.findall(r"\+ (\w+) *: (\S+).*\r\n *Serial Number : (\w+) *\r\n *H/W Revision *: *(\S+) *\r\n *H/W Option *: (\S+)", hardware_rst)
        if hardware:
            for x in hardware:
                hardware_list.append({"ip": ip, "slot": x[0], "card": x[1], "serial_num": str(x[2]), "hw_revision": x[3], "hw_option": x[4]})
    if run_time != "NA":
        # 2 days, 1 hour, 58 minutes, 41 seconds
        if "day" not in run_time:
            d = 0
        else:
            d = int(re.findall(r"(\d+) day", run_time)[0])
        if "hour" not in run_time:
            h = 0
        else:
            h = int(re.findall(r"(\d+) hour", run_time)[0])
        if "minute" not in run_time:
            m = 0
        else:
            m = int(re.findall(r"(\d+) minute", run_time)[0])
        if "second" not in run_time:
            s = 0
        else:
            s = int(re.findall(r"(\d+) second", run_time)[0])
        seconds = str(86400*d + 3600*h + 60*m + s)
        #t_list = [int(x) for x in re.sub("[a-zA-Z ]", "", run_time).split(",")]
        #t_len = len(t_list)
        #for x in range(4-t_len):
        #    t_list.insert(0, 0)
        #seconds = str(86400*t_list[0] + 3600*t_list[1] + 60*t_list[2] + t_list[3])
    else:
        seconds = "0"
    if dswp_status != "Up" or cfpal_status != "OK" or system_status != "Up":
        ne_info_list.append({"ip":ip, "status":"Fail", "version":version, "time":run_time, "seconds": seconds, "dswp":dswp_status, "cfpal":cfpal_status, "system":system_status})
    else:
        ne_info_list.append({"ip":ip, "status":"Pass", "version":version, "time":run_time, "seconds": seconds, "dswp":dswp_status, "cfpal":cfpal_status, "system":system_status})

if __name__ == '__main__':
    # temp_path = r"E:\Study\Python\get_available_ne\temp.html"
    # html_path = r"E:\Study\Python\get_available_ne\available_ne.html"
    temp_path = r"E:\Temp\temp.html"
    html_path = r"E:\Temp\available_ne.html"
    ne_flag_list = ["180", "130", "121", "150", "122"]
    try:
        for flag in ne_flag_list:
            locals()["s_" + flag] = my_thread(func=search_ne, args=(flag,), name="s_"+flag)
            locals()["s_" + flag].start()
        for flag in ne_flag_list:
            locals()["s_"+flag].join()
        for flag in ne_flag_list:
            if locals()["s_"+flag].exitcode == 1:
                raise Exception(locals()["s_"+flag].exc_traceback)
        print("Thread %s ended." % threading.current_thread().name)
        sys.stdout.flush()
    except Exception as e:
        raise e

    db = pymysql.connect(host="172.18.98.199", user="test", password="eci_test", db="test", port=3306)
    cursor = db.cursor()
    cursor.execute("TRUNCATE `available_ne`;")
    cursor.execute("TRUNCATE `ne_inventory`;")
    db.commit()
    with open(temp_path, "r", encoding='utf-8') as f:
        html_doc = f.read()
    soup = bs(html_doc, 'lxml')
    for ne_info in ne_info_list:
        sql = "INSERT INTO `test`.`available_ne` (`ip`, `status`, `version`, `time`, `seconds`, `dswp`, `cfpal`, `system`) VALUES ('"+ne_info["ip"]+"', '"+ne_info["status"]+"', '"+ne_info["version"]+"', '"+ne_info["time"]+"', '"+ne_info["seconds"]+"', '"+ne_info["dswp"]+"', '"+ne_info["cfpal"]+"', '"+ne_info["system"]+"');"
        cursor.execute(sql)
        db.commit()
        soup.table.append(soup.new_tag("tr"))
        tr = soup.find_all("tr")[-2]
        if ne_info["status"] == "Pass":
            tr["class"] = "pass"
        else:
            tr["class"] = "fail"
        for x in ne_info:
            if x != "status":
                tr.append(soup.new_tag("td"))
                soup.find_all("td")[-1].string = ne_info[x]
    for card_info in hardware_list:
        sql = "INSERT INTO `test`.`ne_inventory` (`ip`, `slot`, `card`, `serial_num`, `hw_revision`, `hw_option`) VALUES ('"+card_info["ip"]+"', '"+card_info["slot"]+"', '"+card_info["card"]+"', '"+card_info["serial_num"]+"', '"+card_info["hw_revision"]+"', '"+card_info["hw_option"]+"');"
        cursor.execute(sql)
        db.commit()
        soup.find_all('table')[1].append(soup.new_tag('tr'))
        tr = soup.find_all('tr')[-1]
        print(card_info)
        for x in card_info:
            tr.append(soup.new_tag('td'))
            soup.find_all('td')[-1].string = card_info[x]
    db.close()
    soup.find_all('span')[1].string = str(len(hardware_list))
    for ips in ne_excluded_dict:
        ne_excluded_dict[ips].sort(key=lambda i:(int(i.split(".")[0])*256*256*256+int(i.split(".")[1])*256*256+int(i.split(".")[2])*256+int(i.split(".")[3])))
    unknown_ip_number = 0
    for ips in ne_excluded_dict:
        unknown_ip_number += len(ne_excluded_dict[ips])
        soup.find_all('table')[-1].append(soup.new_tag("tr"))
        tr = soup.find_all("tr")[-1]
        tr.append(soup.new_tag("th"))
        soup.find_all("th")[-1].string = ips
        tr.append(soup.new_tag("td"))
        soup.find_all("td")[-1].string = ", ".join(ne_excluded_dict[ips])
    soup.find_all('span')[-1].string = str(unknown_ip_number)
    with open(html_path, "w", encoding='utf-8') as f:
        f.write(soup.prettify())