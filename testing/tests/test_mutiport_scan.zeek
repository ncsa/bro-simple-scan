# @TEST-EXEC: zeek -r $TRACES/multiport_scan.pcap ../../../scripts %INPUT
# @TEST-EXEC: zeek-cut src p note msg sub < notice.log > notice.tmp && mv notice.tmp notice.log
# @TEST-EXEC: btest-diff notice.log
redef Notice::ignored_types += {Site::New_Used_Address_Space};
redef Site::local_nets = {
    192.168.0.0/16,
    10.10.0.0/16,
};

redef Site::darknet_address_space = {
    10.10.0.0/16,
};
