package wgembed

import (
	"fmt"
	"net"
	"strings"

	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

func (wg *WireGuardInterfaceImpl) AddPeer(publicKey string, addressCIDR string) error {
	key, err := wgtypes.ParseKey(publicKey)
	if err != nil {
		return errors.Wrapf(err, "bad public key %v", publicKey)
	}

	addresses := strings.Split(addressCIDR, ",")
	parsedAddresses := make([]net.IPNet, 0, len(addresses))
	for _, addr := range addresses {
		_, allowedIPs, err := net.ParseCIDR(strings.TrimSpace(addr))
		if err != nil || allowedIPs == nil {
			return errors.Wrap(err, "bad CIDR value for AllowedIPs")
		}
		parsedAddresses = append(parsedAddresses, *allowedIPs)
	}

	return wg.configure(func(config *wgtypes.Config) error {
		config.ReplacePeers = false
		config.Peers = []wgtypes.PeerConfig{
			{
				PublicKey:         key,
				AllowedIPs:        parsedAddresses,
				ReplaceAllowedIPs: true,
			},
		}
		return nil
	})
}

func (wg *WireGuardInterfaceImpl) ListPeers() ([]wgtypes.Peer, error) {
	device, err := wg.Device()
	if err != nil {
		return nil, err
	}
	return device.Peers, nil
}

func (wg *WireGuardInterfaceImpl) RemovePeer(publicKey string) error {
	key, err := wgtypes.ParseKey(publicKey)
	if err != nil {
		return errors.Wrap(err, "bad public key")
	}
	return wg.configure(func(config *wgtypes.Config) error {
		config.ReplacePeers = false
		config.Peers = []wgtypes.PeerConfig{
			{
				Remove:    true,
				PublicKey: key,
			},
		}
		return nil
	})
}

func (wg *WireGuardInterfaceImpl) HasPeer(publicKey string) bool {
	peers, err := wg.ListPeers()
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

func (wg *WireGuardInterfaceImpl) Peer(publicKey string) (*wgtypes.Peer, error) {
	peers, err := wg.ListPeers()
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
func (wg *WireGuardInterfaceImpl) PublicKey() (string, error) {
	device, err := wg.Device()
	if err != nil {
		return "", err
	}
	return device.PublicKey.String(), nil
}

func (wg *WireGuardInterfaceImpl) Port() (int, error) {
	device, err := wg.Device()
	if err != nil {
		return 0, err
	}
	return device.ListenPort, nil
}

func (wg *WireGuardInterfaceImpl) configure(cb func(*wgtypes.Config) error) error {
	// TODO: concurrency
	// s.lock.Lock()
	// defer s.lock.Unlock()
	next := wgtypes.Config{}
	if err := cb(&next); err != nil {
		return errors.Wrap(err, "failed to get next wireguard config")
	}
	return wg.client.ConfigureDevice(wg.Name(), next)
}
