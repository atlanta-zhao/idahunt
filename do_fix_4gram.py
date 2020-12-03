#-*- coding = utf-8 -*-
import os
import time
import subprocess
import sys
import shlex

GBK = 'gbk'
UTF8 = 'utf-8'

current_encoding = UTF8
'''
INPUT_PE = "ccc.exe"
os.system("mkdir ")
'''
def hms_string(sec_elapsed):
    h = int(sec_elapsed / (60 * 60))
    m = int((sec_elapsed % (60 * 60)) / 60)
    s = sec_elapsed % 60.
    return "{}:{:>02}:{:>05.2f}".format(h, m, s)
#print 1
#tmp = os.popen(r'python3 D:\new_folder\Git_my\malware_analysis\idahunt_my\idahunt\idahunt.py --inputdir D:\new_folder\Git_my\malware_analysis\sample --scripts D:\new_folder\Git_my\malware_analysis\idahunt_my\idahunt\flatten_instrument.py --analyse').read()
#print tmp
#sys.stdout.flush()
#tmp = os.popen(r'python3 D:\new_folder\Git_my\malware_analysis\idahunt_my\idahunt\idahunt.py --inputdir D:\new_folder\Git_my\malware_analysis\sample\crafted --scripts D:\new_folder\Git_my\malware_analysis\idahunt_my\idahunt\recover_env.py --analyse').read()
#print tmp
#sys.stdout.flush()

tmp1 = subprocess.Popen(['python3',r'D:\new_folder\Git_my\malware_analysis\idahunt_my\idahunt\idahunt.py',
'--inputdir',r'D:\new_folder\Git_my\malware_analysis\sample',
'--scripts',r'D:\new_folder\Git_my\malware_analysis\idahunt_my\idahunt\flatten_instrument.py','--analyse'],
stdout = subprocess.PIPE,
stderr = subprocess.PIPE,
bufsize = 1
)

while tmp1.poll() is None:         
    r = tmp1.stdout.readline().decode(current_encoding)
    sys.stdout.write(r)
    sys.stdout.flush()  
if tmp1.poll() != 0:                      
    err = tmp1.stderr.read().decode(current_encoding)
    sys.stdout.write(err)
    sys.stdout.flush()   

tmp2 = subprocess.Popen(['python3',r'D:\new_folder\Git_my\malware_analysis\idahunt_my\idahunt\idahunt.py',
'--inputdir',r'D:\new_folder\Git_my\malware_analysis\sample\crafted',
'--scripts',r'D:\new_folder\Git_my\malware_analysis\idahunt_my\idahunt\recover_env.py','--analyse'],
stdout = subprocess.PIPE,
stderr = subprocess.PIPE,
bufsize = 1)

while tmp2.poll() is None:
    r = tmp2.stdout.readline().decode(current_encoding)
    sys.stdout.write(r)
    sys.stdout.flush()
if tmp2.poll() != 0:
    err = tmp2.stdout.readline().decode(current_encoding)
    sys.stdout.write(err)
    sys.stdout.flush()

#tmp = os.popen(r'python3 .\idahunt.py --inputdir D:\new_folder\Git_my\malware_analysis\sample\ --scripts D:\new_folder\Git_my\malware_analysis\idahunt_my\idahunt\4gram_traverse.py --analyse').read()
#print tmp
"""
for i in range(1025):
    tmp = os.popen(r'python3 .\idahunt.py --inputdir D:\new_folder\Git_my\malware_analysis\sample\crafted\ --scripts D:\new_folder\Git_my\malware_analysis\idahunt_my\idahunt\4gram_fix.py --analyse').read()
    print tmp
    tmp = os.popen(r'python3 .\idahunt.py --inputdir D:\new_folder\Git_my\malware_analysis\sample\crafted\  --cleanup --temp-cleanup').read()
    print tmp
"""
'''
start_time = time.time()
tmp = os.popen(r'python3 .\4gram_fix.py --fixfile "10"').read()
print tmp
end_time = time.time()
print "Took {} to execute this".format(hms_string(end_time - start_time))
'''
print "woc nb!"