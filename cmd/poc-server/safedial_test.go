package main

import (
"net/netip"
"testing"
)

func TestIsPublicIP(t *testing.T) {
cases := []struct {
ip     string
public bool
reason string
}{
// Публичные — должны проходить
{"8.8.8.8", true, "Google DNS"},
{"1.1.1.1", true, "Cloudflare"},
{"2a02:26f0:e80:593::356e", true, "Microsoft IPv6"},
{"20.112.250.133", true, "Microsoft IPv4"},

// Непубличные — должны отклоняться
{"127.0.0.1", false, "loopback"},
{"127.1.2.3", false, "loopback /8"},
{"::1", false, "loopback v6"},
{"10.0.0.1", false, "private 10/8"},
{"172.16.0.1", false, "private 172.16/12"},
{"192.168.1.1", false, "private 192.168/16"},
{"169.254.169.254", false, "link-local (AWS metadata)"},
{"fe80::1", false, "link-local v6"},
{"100.64.0.1", false, "CGNAT"},
{"100.127.255.254", false, "CGNAT upper bound"},
{"198.18.0.1", false, "benchmark"},
{"198.19.255.254", false, "benchmark upper"},
{"192.0.2.1", false, "TEST-NET-1"},
{"198.51.100.1", false, "TEST-NET-2"},
{"203.0.113.1", false, "TEST-NET-3"},
{"240.0.0.1", false, "reserved 240/4"},
{"255.255.255.255", false, "broadcast"},
{"0.0.0.0", false, "unspecified"},
{"::", false, "unspecified v6"},
{"2001:db8::1", false, "documentation v6"},
{"ff02::1", false, "multicast v6"},
{"224.0.0.1", false, "multicast v4"},

// Граничные случаи
{"::ffff:127.0.0.1", false, "IPv4-mapped loopback"},
{"::ffff:8.8.8.8", true, "IPv4-mapped public"},
{"fe80::1%eth0", false, "zone identifier"},
{"100.63.255.255", true, "just below CGNAT"},
{"100.128.0.0", true, "just above CGNAT"},
}

for _, c := range cases {
ip, err := netip.ParseAddr(c.ip)
if err != nil {
t.Fatalf("parse %q: %v", c.ip, err)
}
got := isPublicIP(ip)
if got != c.public {
t.Errorf("%s (%s): got %v, want %v", c.ip, c.reason, got, c.public)
}
}
}
