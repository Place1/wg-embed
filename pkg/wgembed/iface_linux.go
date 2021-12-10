//go:build linux
// +build linux

package wgembed

import (
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"
)

func (wg *WireGuardInterfaceImpl) Up() error {
	link, err := netlink.LinkByName(wg.Name())
	if err != nil {
		return errors.Wrap(err, "failed to find wireguard interface")
	}

	if err := netlink.LinkSetUp(link); err != nil {
		return errors.Wrap(err, "failed to bring wireguard interface up")
	}

	if err := netlink.LinkSetMTU(link, 1420); err != nil {
		return errors.Wrap(err, "failed to set wireguard mtu")
	}

	logrus.Debug("set interface up")

	return nil
}

func (wg *WireGuardInterfaceImpl) setIP(ip string) error {
	link, err := netlink.LinkByName(wg.Name())
	if err != nil {
		return errors.Wrap(err, "failed to find wireguard interface")
	}

	linkaddr, err := netlink.ParseAddr(ip)
	if err != nil {
		return errors.Wrap(err, "failed to parse wireguard interface ip address")
	}

	if err := netlink.AddrAdd(link, linkaddr); err != nil {
		return errors.Wrap(err, "failed to set ip address of wireguard interface")
	}

	return nil
}
