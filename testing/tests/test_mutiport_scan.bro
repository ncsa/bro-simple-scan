# @TEST-EXEC: bro -r $TRACES/multiport_scan.pcap ../../../scripts %INPUT
# @TEST-EXEC: btest-diff notice.log
redef Site::local_nets = {
    192.168.0.0/16,
    10.10.0.0/16,
};

redef Site::darknet_address_space = {
    10.10.0.0/16,
};
