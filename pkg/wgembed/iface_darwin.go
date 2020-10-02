// +build darwin

package wgembed

import "log"

func (wg *WireGuardInterfaceImpl) Up() error {
	log.Println("wg.Up() is a no-op on macos")
	return nil
}

func (wg *WireGuardInterfaceImpl) setIP(ip string) error {
	return nil
}
