//go:build windows
// +build windows

package wgembed

import "log"

func (wg *WireGuardInterfaceImpl) Up() error {
	log.Println("wg.Up() is a no-op on windows")
	return nil
}

func (wg *WireGuardInterfaceImpl) setIP(ip string) error {
	return nil
}
