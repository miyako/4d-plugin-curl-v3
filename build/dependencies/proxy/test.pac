function FindProxyForURL(url, host) {
    if (host === "bypass.invalid") return "DIRECT";
    return "PROXY pac.invalid:3128; SOCKS5 socks.invalid:1080; DIRECT";
}
