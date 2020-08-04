# @TEST-EXEC: zeek -C -r $TRACES/scan_with_zero_windows.pcap ../../../scripts %INPUT
# @TEST-EXEC: zeek-cut src p note msg sub < notice.log > notice.tmp && mv notice.tmp notice.log
# @TEST-EXEC: btest-diff notice.log
redef Notice::ignored_types += {Site::New_Used_Address_Space};
redef Scan::local_scan_threshold=5;
redef Site::local_nets = {
    10.0.0.0/24
};
