protoperf
=========

protoperf is a tool to measure the throughput of a network connection, very
similar to [iperf][1]. But since iperf only supports TCP and UDP and I needed to
compare TCP with [UDT][2] I wrote protoperf.


Example
-------

To run protoperf as a server:

    $ protoperf -s

To run a client and send 100M to server running on localhost:

    $ protoperf -c localhost -n 100M


Options
-------

**TODO**


[1]: https://iperf.fr/
[2]: http://udt.sourceforge.net/
