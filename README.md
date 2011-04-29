NAME
----

node-knockd - A simple port knock daemon written for node


INSTALLATION
-----------

Make sure the pcap binding is installed (npm install pcap), Modify config.js to specify knock rules and their behavior.  knockd.conf is an upstart script to handle launching the daemon.  If launching by hand: node knockd.js xxx where xxx is the name of the interface to listen on.

Included is a set of iptables rules that will work with the sample config, import using iptables-restore.  The rules create a chain called sshknock, all ssh traffic is forwarded to that chain that has a default DROP policy.  The sample config modifies the sshknock chain to allow traffic to a given IP upon a successful knock.  The config can be extended to knock protect any TCP port (UDP isn't supported right now)


NOTES
-----

Doesn't support TCP flag detection at the moment
Doesn't support UDP traffic


