# bfshell -b ~/mason/tofino-dyso/control/netcache/print_regs.py > netcache.log
    
import time

init_time = int(round(time.time() * 1000))
round_size = 10
print("Round size : ", round_size, " (ms)")
round_time = round_size
while (True):
    curr_time = int(round(time.time() * 1000))
    if (curr_time - init_time > round_time):
        round_time += round_size # seconds
        val_hit = bfrt.netcache.nc_pipe_1.Pipe1SwitchIngress.reg_hit_number.get(0, from_hw=True).data[b'Pipe1SwitchIngress.reg_hit_number.f1'][0]
        val_total = bfrt.netcache.nc_pipe_1.Pipe1SwitchIngress.reg_total_number.get(0, from_hw=True).data[b'Pipe1SwitchIngress.reg_total_number.f1'][0]
        if (val_total != 0):
            print("SIGNAL", curr_time, val_hit, val_total, val_hit * 1.0 / (val_total+1))
        
        bfrt.netcache.nc_pipe_1.Pipe1SwitchIngress.reg_hit_number.clear()
        bfrt.netcache.nc_pipe_1.Pipe1SwitchIngress.reg_total_number.clear()