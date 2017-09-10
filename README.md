# Bro simple scan

This is the 'simplest thing that could possibly work' scan detection script for
bro.  The entire script is about 300 lines and written to be as understandable
as possible.

While simple, it also tries to do the least amount of work that it needs to in
order to detect scans.

It should work up until about 8 /16 networks before the manager is overloaded,
but it is possible that with the right policy it can scale even higher.  Broker
will enable a version to be used that scales out the analysis to multiple data
nodes, once broker is ready.

## Configuration

See the comments in scan.bro for all the tunables.  Most likely one would want
to modify the various `threshold` variables for different environments.

Properly configuring the darknet plugin as described under
https://github.com/ncsa/bro-is-darknet will enable faster detection of scans.

False positives for outbound scans for heavy bittorrent users are common, but
that is fixable with the right scan policy to ignore their 'scans'.

## Notice policy

The notice type specific suppression intervals are used by the script in order
to ignore further scan traffic from hosts that have set off scan notices.

If you don't care about repeat notices once per hour, set the supression
interval to a higher value.

    redef Notice::type_suppression_intervals += {
        [Scan::Port_Scan]           = 4hrs,
        [Scan::Address_Scan]        = 4hrs,
        [Scan::Random_Scan]         = 4hrs,
    };

If you are blocking scanners using a default duration of less than 1 hour, set
the intervals to match.  Otherwise once the block expires, bro will still be
ignoring the scanner.

## Example scan policy

    # Ignore (via 'break') scan attempts for common noisy destination ports that are already blocked
    # but don't ignore outbound scans TO these ports.
    const ignore_scan_ports: set[port] = { 23/tcp, 445/tcp };

    hook Scan::scan_policy(scanner: addr, victim: addr, scanned_port: port)
    {
        if ((scanned_port in ignore_scan_ports) && (!Site::is_local_addr(scanner)))
            break;
    }

