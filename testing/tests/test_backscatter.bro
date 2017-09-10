# @TEST-EXEC: bro -r $TRACES/backscatter.trace ../../../scripts %INPUT
# @TEST-EXEC: touch notice.log #No output is expected
# @TEST-EXEC: btest-diff notice.log
redef Site::local_nets = {
    192.150.0.0/16,
};
