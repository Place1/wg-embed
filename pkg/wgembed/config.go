package wgembed

import (
	"io/ioutil"
	"net"
	"strings"

	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
	"gopkg.in/ini.v1"
)

type ConfigFile struct {
	Interface IfaceConfig
	Peers     []PeerConfig    `ini:"Peer,nonunique"`
	wgconfig  *wgtypes.Config `ini:"-"`
}

type IfaceConfig struct {
	PrivateKey string
	Address    []string
	ListenPort *int
	DNS        []string
}

type PeerConfig struct {
	PublicKey  string
	AllowedIPs []string
	Endpoint   *string
}

func ReadConfig(path string) (*ConfigFile, error) {

	opts := &ConfigFile{
		Interface: IfaceConfig{
			DNS: []string{},
		},
		Peers: []PeerConfig{},
	}

	bytes, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, errors.Wrap(err, "failed to read wireguard config file")
	}

	if err := opts.parse(bytes); err != nil {
		return nil, err
	}

	if err := opts.load(); err != nil {
		return nil, err
	}

	return opts, nil
}

func (c *ConfigFile) parse(config []byte) error {
	opt := ini.LoadOptions{AllowNonUniqueSections: true}
	f, err := ini.LoadSources(opt, config)
	if err != nil {
		return errors.Wrap(err, "failed to read wireguard config file")
	}

	err = f.MapTo(c)
	if err != nil {
		return errors.Wrap(err, "failed to map wireguard config file")
	}

	return nil
}

func (c *ConfigFile) load() error {
	privateKey, err := wgtypes.ParseKey(c.Interface.PrivateKey)
	if err != nil {
		return errors.Wrap(err, "bad private key")
	}

	peers := []wgtypes.PeerConfig{}
	for _, peer := range c.Peers {
		key, err := wgtypes.ParseKey(peer.PublicKey)
		if err != nil {
			return errors.Wrap(err, "bad public key")
		}

		allowedIPs := []net.IPNet{}
		for _, ip := range peer.AllowedIPs {
			_, ipnet, err := net.ParseCIDR(ip)
			if err != nil {
				return errors.Wrapf(err, "bad allowed ip: %s", ip)
			}
			allowedIPs = append(allowedIPs, *ipnet)
		}

		var endpoint *net.UDPAddr
		if peer.Endpoint != nil {
			udpaddr, err := net.ResolveUDPAddr("udp", *peer.Endpoint)
			if err != nil {
				return errors.Wrap(err, "failed to parse endpoint address")
			}
			endpoint = udpaddr
		}

		peers = append(peers, wgtypes.PeerConfig{
			PublicKey:  key,
			AllowedIPs: allowedIPs,
			Endpoint:   endpoint,
		})
	}

	c.wgconfig = &wgtypes.Config{
		PrivateKey: &privateKey,
		ListenPort: c.Interface.ListenPort,
		Peers:      peers,
	}

	return nil
}

func (c *ConfigFile) Config() (*wgtypes.Config, error) {
	if c.wgconfig == nil {
		if err := c.load(); err != nil {
			return nil, err
		}
	}
	return c.wgconfig, nil
}

func (c *ConfigFile) String() string {
	var f *ini.File
	if err := ini.ReflectFrom(f, c); err != nil {
		logrus.Fatal(err)
	}
	return strings.Join(f.SectionStrings(), "\n\n")
}
