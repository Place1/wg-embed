package wgembed

import "golang.zx2c4.com/wireguard/wgctrl/wgtypes"

type NoOpWireguardInterface struct {
}

func NewNoOpInterface() WireGuardInterface {
	return &NoOpWireguardInterface{}
}

func (wg *NoOpWireguardInterface) LoadConfig(config *ConfigFile) error {
	return nil
}

func (wg *NoOpWireguardInterface) AddPeer(publicKey string, addressCIDR string) error {
	return nil
}

func (wg *NoOpWireguardInterface) ListPeers() ([]wgtypes.Peer, error) {
	return []wgtypes.Peer{}, nil
}

func (wg *NoOpWireguardInterface) RemovePeer(publicKey string) error {
	return nil
}

func (wg *NoOpWireguardInterface) PublicKey() (string, error) {
	return "<publickey>", nil
}

func (wg *NoOpWireguardInterface) Close() error {
	return nil
}
