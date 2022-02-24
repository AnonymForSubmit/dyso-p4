# /usr/bin/python3

import subprocess
import os
import time

####### your passowrd of SUDO privilege #######
pwd='yourSudoPassword'
###############################################

print("*** Run RxProgram to receive DP's HH reports")
subprocess.call('echo {} | sudo -S {}'.format(pwd, 'sudo ./control/netcache/cpp/netcacheHH &'), shell=True)
print("->done\n")
time.sleep(10)

print("*** Start setup NetCache's ports")
subprocess.run(["bash", "./scripts/netcache_setup.sh"])
print("*** Loading register values for query generation")
subprocess.run(["bash", "./scripts/netcache_load_data.sh"])
print("*** Start query packet generators")
subprocess.run(["bash", "./scripts/netcache_start_pktgen.sh"])

print("*** Record hit-rates")
subprocess.call('{}'.format('bfshell -b ./control/netcache/print_regs.py > netcache.log &'), shell=True)
time.sleep(10)

# variable (speed of evolution of popularity)
interval_size = 5 # seconds
offset_size = 1000 # offset size
total_interval = 100 # 100 seconds to run experiment

# constants
round = 0 # round
while (round < int(total_interval / interval_size)):
    time.sleep(interval_size)
    round = round + 1
    offset = round * offset_size
    print("offset: ", offset)
    subprocess.run(["bash", "./netcache_change_offset.sh", str(offset)])
    
time.sleep(5)
subprocess.run(["bash", "./scripts/netcache_stop_pktgen.sh"])
subprocess.run(["pkill", "-f", "print_regs"])
subprocess.call('echo {} | sudo -S {}'.format(pwd, 'pkill -f netcache'), shell=True)
