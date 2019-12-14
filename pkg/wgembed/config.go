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
	Peers     []PeerConfig
	wgconfig  *wgtypes.Config
}

type IfaceConfig struct {
	PrivateKey string
	Address    string
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
	// this is harder than it needs to be because of this bug
	// https://github.com/go-ini/ini/issues/190

	sections := []string{}
	for _, s := range strings.Split(string(config), "[") {
		if s != "" {
			sections = append(sections, "["+s)
		}
	}

	for _, s := range sections {
		if s == "" {
			continue
		}

		f, err := ini.Load([]byte(s))
		if err != nil {
			return errors.Wrap(err, "failed to read wireguard config file")
		}
		section := f.Sections()[1]

		switch section.Name() {
		case ini.DEFAULT_SECTION:
			// nothing to do here (case so that we don't warn for it)
		case "Interface":
			if err := section.MapTo(&c.Interface); err != nil {
				return errors.Wrap(err, "failed to parse Interface config")
			}
		case "Peer":
			peer := PeerConfig{}
			if err := section.MapTo(&peer); err != nil {
				return errors.Wrap(err, "failed to parse Interface config")
			}
			c.Peers = append(c.Peers, peer)
		default:
			logrus.Warnf("skipping unknown config section: %s", section.Name())
		}
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

func (c *ConfigFile) Config() wgtypes.Config {
	return *c.wgconfig
}

func (c *ConfigFile) String() string {
	var f *ini.File
	if err := ini.ReflectFrom(f, c); err != nil {
		logrus.Fatal(err)
	}
	return strings.Join(f.SectionStrings(), "\n\n")
}
