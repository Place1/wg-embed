package wgembed

import (
	"fmt"
	"net"

	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

func AddPeer(iface string, publicKey string, addressCIDR string) error {
	key, err := wgtypes.ParseKey(publicKey)
	if err != nil {
		return errors.Wrapf(err, "bad public key %v", publicKey)
	}
	_, allowedIPs, err := net.ParseCIDR(addressCIDR)
	if err != nil || allowedIPs == nil {
		return errors.Wrap(err, "bad CIDR value for AllowedIPs")
	}
	if HasPeer(iface, key.String()) {
		RemovePeer(iface, key.String())
	}
	return configure(iface, func(config *wgtypes.Config) error {
		config.ReplacePeers = false
		config.Peers = []wgtypes.PeerConfig{
			wgtypes.PeerConfig{
				PublicKey:  key,
				AllowedIPs: []net.IPNet{*allowedIPs},
			},
		}
		return nil
	})
}

func ListPeers(iface string) ([]wgtypes.Peer, error) {
	device, err := wgdevice(iface)
	if err != nil {
		return nil, err
	}
	return device.Peers, nil
}

func RemovePeer(iface string, publicKey string) error {
	key, err := wgtypes.ParseKey(publicKey)
	if err != nil {
		return errors.Wrap(err, "bad public key")
	}
	return configure(iface, func(config *wgtypes.Config) error {
		config.ReplacePeers = false
		config.Peers = []wgtypes.PeerConfig{
			wgtypes.PeerConfig{
				Remove:    true,
				PublicKey: key,
			},
		}
		return nil
	})
}

func HasPeer(iface string, publicKey string) bool {
	peers, err := ListPeers(iface)
	if err != nil {
		logrus.Error(errors.Wrap(err, "failed to list peers"))
		return false
	}
	for _, peer := range peers {
		if peer.PublicKey.String() == publicKey {
			return true
		}
	}
	return false
}

func Peer(iface string, publicKey string) (*wgtypes.Peer, error) {
	peers, err := ListPeers(iface)
	if err != nil {
		return nil, err
	}
	for _, peer := range peers {
		if peer.PublicKey.String() == publicKey {
			return &peer, nil
		}
	}
	return nil, fmt.Errorf("peer with public key '%s' not found", publicKey)
}

// PublicKey returns the currently configured wireguard public key
func PublicKey(iface string) (string, error) {
	device, err := wgdevice(iface)
	if err != nil {
		return "", err
	}
	return device.PublicKey.String(), nil
}

func Port(iface string) (int, error) {
	device, err := wgdevice(iface)
	if err != nil {
		return 0, err
	}
	return device.ListenPort, nil
}

func wgdevice(iface string) (*wgtypes.Device, error) {
	client, err := wgctrl.New()
	if err != nil {
		logrus.Fatal(errors.Wrap(err, "failed to create wgctrl"))
	}
	return client.Device(iface)
}

func configure(iface string, cb func(*wgtypes.Config) error) error {
	// TODO: concurrency
	// s.lock.Lock()
	// defer s.lock.Unlock()
	client, err := wgctrl.New()
	if err != nil {
		logrus.Fatal(errors.Wrap(err, "failed to create wgctrl"))
	}

	next := wgtypes.Config{}
	if err := cb(&next); err != nil {
		return errors.Wrap(err, "failed to get next wireguard config")
	}
	return client.ConfigureDevice(iface, next)
}
