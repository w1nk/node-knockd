var config = {
    openSSH: {
        sequence        : [ 7000,8000,9000 ],
        seq_timeout     : 10,
        command         : '/sbin/iptables -I sshknock 1 -s %IP% -p tcp --dport 22 -j ACCEPT',
        tcpflags        : 'syn',
        cmd_timeout     : 30,
        stop_command    : '/sbin/iptables -D sshknock -s %IP% -p tcp --dport 22 -j ACCEPT'
    },
    flush: {
        sequence        : [4000,4001,4002],
        seq_timeout     : 10,
        command         : '/sbin/iptables -F',
        tcpflags        : 'syn'
    },
    closeSSH: {
        sequence        : [9000,8000,7000],
        seq_timeout     : 5,
        command         : '/sbin/iptables -D sshknock -s %IP% -p tcp --dport 22 -j ACCEPT',
        tcpflags        : 'syn'
    }
};

exports.config = config;