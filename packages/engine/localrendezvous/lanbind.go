// SPDX-FileCopyrightText: 2026 The SendBeam contributors <https://sendbeam.dev>
// SPDX-License-Identifier: AGPL-3.0-only

package localrendezvous

import (
	"errors"
	"net"
)

// LANBindAddr returns an "ip:0" bind address for the first usable
// non-loopback IPv4 address on an up interface, for use as Config.BindAddr
// when a local rendezvous server must be reachable by other devices on the
// LAN (V21-PR06: offline pairing invitations carry this address, so binding
// loopback would hand the joiner an address it cannot reach).
//
// It prefers global-unicast IPv4 over link-local, and returns an error when
// no suitable interface exists (e.g. a host with only loopback up).
func LANBindAddr() (string, error) {
	ifs, err := net.Interfaces()
	if err != nil {
		return "", err
	}
	var linkLocal string
	for _, ifi := range ifs {
		if ifi.Flags&net.FlagUp == 0 {
			continue
		}
		if ifi.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, err := ifi.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			var ip net.IP
			switch v := a.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			default:
				continue
			}
			ip = ip.To4()
			if ip == nil || ip.IsLoopback() {
				continue
			}
			bind := ip.String() + ":0"
			if ip.IsLinkLocalUnicast() {
				if linkLocal == "" {
					linkLocal = bind
				}
				continue
			}
			return bind, nil
		}
	}
	if linkLocal != "" {
		return linkLocal, nil
	}
	return "", errors.New("localrendezvous: no usable LAN interface address (only loopback is up)")
}
