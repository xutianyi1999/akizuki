# akizuki
tun to socks5

Currently supported platforms:
- Windows

Requires wintun.dll dependency https://www.wintun.net/

## Usage
```shell
USAGE:
    akizuki.exe [OPTIONS] --socks5-server <SOCKS5_SERVER> <SUBCOMMAND>

OPTIONS:
    -h, --help                             Print help information
    -s, --socks5-server <SOCKS5_SERVER>    Socks5 server address
    -u, --udp-through-proxy                UDP packet through proxy
    -V, --version                          Print version information

SUBCOMMANDS:
    help         Print this message or the help of the given subcommand(s)
    match        Match ip list proxy
    not-match    Not match ip list proxy
```

Iplist file rules same as https://github.com/17mon/china_ip_list/blob/master/china_ip_list.txt, line breaks separate multiple addresses

example: 
```shell
.\akizuki.exe -s 10.0.0.1:1080 not-match .\iplist.txt
```
