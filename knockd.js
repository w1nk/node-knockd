var sys = require("sys");
var pcap = require("pcap");
var config = require("./config").config;
var util = require("util");
var exec = require('child_process').exec;

var pcap_session;
var ports = [];
var sessions = [];
var ifaces = [];


if (process.argv.length < 3) {
    util.log("please provide an interface");
    process.exit(1);
}

pcap_session = pcap.createSession(process.argv[2], "tcp");

pcap_session.findalldevs().forEach(function (dev) {
    if (pcap_session.device_name === dev.name)
    {
        dev.addresses.forEach(function (address) {
            ifaces.push(address.addr);
        });
    }
});

pcap_session.on('packet', function (raw_packet) {
    var packet = pcap.decode.packet(raw_packet);

    for(var i = 0; i < ifaces.length; i++)
    {
        if(packet.link.ip.saddr == ifaces[i])
            return;
    }

    var tcp = packet.link.ip.tcp;
    if(!tcp) return;

    var dport = tcp.dport;
    var ip = packet.link.ip.saddr;

    //util.log("got a packet from " + ip + " on port " + dport);

    // find the session
    var session = null;
    for(var i = 0; i < sessions.length; i++)
    {
        if(sessions[i].ip == ip)
            session = sessions[i];
    }

    if(!session)
    {
        // find the rule starting on this port
        var rule = null;
        for(var key in config)
        {
            if(config[key].sequence[0] == dport)
                rule = config[key];
        }

        if(rule)
        {
            util.log("creating session for " + ip + " expecting: " + util.inspect(rule.sequence));
            var now = Math.floor((new Date().getTime()) / 1000);
            session = {
                ip: ip,
                sequence: [dport],
                seq_timeout: (now + rule.seq_timeout),
                rule: rule
            };
            sessions.push(session);
        }
        else
            return;
    }
    else
    {
        session.sequence.push(dport);
        //util.log("found session for " + ip);
        var current = session.sequence;
        var required = session.rule.sequence;
        var now = Math.floor((new Date().getTime()) / 1000);

        if(now > session.seq_timeout)
        {
            removeSession(session);
            return;
        }

        for(var i = 0; i < current.length; i++)
        {
            if(required[i] != current[i])
            {
                removeSession(session);
                return;
            }
        }
        util.log("session is still valid!");

        if(session.sequence.length == session.rule.sequence.length)
        {
            util.log("KNOCK COMPLETE");
            removeSession(session);
            var cmd = session.rule.command;
            cmd.replace("%IP%", ip);
            util.log("execing: " + cmd);
            var child = exec(cmd);

            var stopcmd = session.rule.stop_command;
            var cmd_timeout = session.rule.cmd_timeout;

            if(stopcmd && cmd_timeout)
            {
                stopcmd.replace("%IP%", ip);
                setTimeout(function()
                           {
                               util.log("execing: " + stopcmd);
                               var child = exec(stopcmd);
                           }, (cmd_timeout*1000));
            }
        }
    }
});

var removeSession = function(session)
{
    for(var j = 0; j < sessions.length; j++)
    {
        if(sessions[j].ip == session.ip)
        {
            util.log("removing session for " + session.ip);
            sessions.splice(j, 1);
            return;
        }
    }

}