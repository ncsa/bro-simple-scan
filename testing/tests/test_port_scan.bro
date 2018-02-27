# @TEST-EXEC: bro -C -r $TRACES/port_scan.pcap ../../../scripts %INPUT
# @TEST-EXEC: btest-diff notice.log
redef Notice::ignored_types += {Site::New_Used_Address_Space};
redef Scan::scan_threshold=5;
redef Site::local_nets = {
    192.168.2.22/32
};
