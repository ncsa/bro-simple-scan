# @TEST-EXEC: bro -r $TRACES/backscatter.trace ../../../scripts %INPUT
# @TEST-EXEC: touch notice.log #No output is expected
# @TEST-EXEC: btest-diff notice.log
redef Notice::ignored_types += {Site::New_Used_Address_Space};
redef Site::local_nets = {
    192.150.0.0/16,
};
