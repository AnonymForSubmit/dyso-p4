#! /bin/bash

# port setup
$SDE/run_bfshell.sh -f `pwd`/bootstrap/port_setup

# config pkt_gen
python ~/tools/run_pd_rpc.py `pwd`/control/netcache/config_pktgen.py