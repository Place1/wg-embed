// +build !windows

/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2019 WireGuard LLC. All Rights Reserved.
 */

// modified from https://git.zx2c4.com/wireguard-go

package wgembed

import (
	"net"

	"github.com/pkg/errors"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/ipc"
	"golang.zx2c4.com/wireguard/tun"
	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

type WireGuardInterface interface {
	LoadConfig(config *ConfigFile) error
	AddPeer(publicKey string, addressCIDR []string) error
	ListPeers() ([]wgtypes.Peer, error)
	RemovePeer(publicKey string) error
	PublicKey() (string, error)
	Close() error
}

// WireGuardInterfaceImpl represents a wireguard
// network interface
type WireGuardInterfaceImpl struct {
	device *device.Device
	client *wgctrl.Client
	uapi   net.Listener
	name   string
	config *ConfigFile
}

// New creates a wireguard interface and starts the userspace
// wireguard configuration api
func New(interfaceName string) (WireGuardInterface, error) {
	wg := &WireGuardInterfaceImpl{
		name: interfaceName,
	}

	client, err := wgctrl.New()
	if err != nil {
		return nil, errors.Wrap(err, "failed to create wg client")
	}
	wg.client = client

	tun, err := tun.CreateTUN(wg.name, device.DefaultMTU)
	if err != nil {
		return nil, errors.Wrap(err, "failed to create TUN device")
	}

	// open UAPI file (or use supplied fd)
	fileUAPI, err := ipc.UAPIOpen(wg.name)
	if err != nil {
		return nil, errors.Wrap(err, "UAPI listen error")
	}

	wg.device = device.NewDevice(tun, device.NewLogger(device.LogLevelError, wg.name))

	errs := make(chan error)

	uapi, err := ipc.UAPIListen(wg.name, fileUAPI)
	if err != nil {
		return nil, errors.Wrap(err, "failed to listen on uapi socket")
	}
	wg.uapi = uapi

	go func() {
		for {
			conn, err := uapi.Accept()
			if err != nil {
				errs <- err
				return
			}
			go wg.device.IpcHandle(conn)
		}
	}()

	return wg, nil
}

// LoadConfigFile reads the given wireguard config file
// and configures the interface
func (wg *WireGuardInterfaceImpl) LoadConfigFile(path string) error {
	config, err := ReadConfig(path)
	if err != nil {
		return errors.Wrap(err, "failed to load config file")
	}
	return wg.LoadConfig(config)
}

// LoadConfig takes the given wireguard config object
// and configures the interface
func (wg *WireGuardInterfaceImpl) LoadConfig(config *ConfigFile) error {
	c, err := config.Config()
	if err != nil {
		return errors.Wrap(err, "invalid wireguard config")
	}

	wg.config = config

	if err := wg.client.ConfigureDevice(wg.Name(), *c); err != nil {
		return errors.Wrap(err, "failed to configure wireguard")
	}

	for _, addr := range config.Interface.Address {
		if err := wg.setIP(addr); err != nil {
			return errors.Wrap(err, "failed to set interface ip address")
		}
	}

	if err := wg.Up(); err != nil {
		return errors.Wrap(err, "failed to bring interface up")
	}

	return nil
}

// Config returns the loaded wireguard config file
// can return nil if no config has been loaded
func (wg *WireGuardInterfaceImpl) Config() *ConfigFile {
	return wg.config
}

// Device returns the wgtypes Device, this type contains
// runtime infomation about the wireguard interface
func (wg *WireGuardInterfaceImpl) Device() (*wgtypes.Device, error) {
	return wg.client.Device(wg.Name())
}

// Wait will return a channel that signals when the
// wireguard interface is stopped
func (wg *WireGuardInterfaceImpl) Wait() chan struct{} {
	return wg.device.Wait()
}

// Close will stop and clean up both the wireguard
// interface and userspace configuration api
func (wg *WireGuardInterfaceImpl) Close() error {
	if err := wg.uapi.Close(); err != nil {
		return err
	}
	wg.device.Close()
	wg.client.Close()
	return nil
}

// Name returns the real wireguard interface name e.g. wg0
func (wg *WireGuardInterfaceImpl) Name() string {
	return wg.name
}
