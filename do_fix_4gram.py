import os
import time
'''
INPUT_PE = "ccc.exe"
os.system("mkdir ")
'''
def hms_string(sec_elapsed):
    h = int(sec_elapsed / (60 * 60))
    m = int((sec_elapsed % (60 * 60)) / 60)
    s = sec_elapsed % 60.
    return "{}:{:>02}:{:>05.2f}".format(h, m, s)
#tmp = os.popen(r'python3 .\idahunt.py --inputdir D:\new_folder\Git_my\malware_analysis\sample --scripts D:\new_folder\Git_my\malware_analysis\idahunt_my\idahunt\4gram_traverse.py --analyse').read()
#print tmp
for i in range(1024):
    tmp = os.popen(r'python3 .\idahunt.py --inputdir D:\new_folder\Git_my\malware_analysis\sample\crafted\ --scripts D:\new_folder\Git_my\malware_analysis\idahunt_my\idahunt\4gram_fix.py --analyse').read()
    print tmp
    tmp = os.popen(r'python3 .\idahunt.py --inputdir D:\new_folder\Git_my\malware_analysis\sample\crafted\  --cleanup --temp-cleanup').read()
    print tmp
'''
start_time = time.time()
tmp = os.popen(r'python3 .\4gram_fix.py --fixfile "10"').read()
print tmp
end_time = time.time()
print "Took {} to execute this".format(hms_string(end_time - start_time))
'''