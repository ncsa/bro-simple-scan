# @TEST-EXEC: zeek -C -r $TRACES/port_scan.pcap ../../../scripts %INPUT
# @TEST-EXEC: zeek-cut src p note msg sub < notice.log > notice.tmp && mv notice.tmp notice.log
# @TEST-EXEC: btest-diff notice.log
@ifdef ( Site::private_address_space_is_local )
redef Site::private_address_space_is_local = F;
@endif
redef Notice::ignored_types += {Site::New_Used_Address_Space};
redef Scan::scan_threshold=5;
redef Site::local_nets = {
    192.168.2.22/32
};
