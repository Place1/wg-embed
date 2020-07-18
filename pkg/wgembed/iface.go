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

// WireGuardInterface represents a wireguard
// network interface
type WireGuardInterface struct {
	device *device.Device
	uapi   net.Listener
	name   string
	config *ConfigFile
}

// New creates a wireguard interface and starts the userspace
// wireguard configuration api
func New(interfaceName string) (*WireGuardInterface, error) {
	wg := &WireGuardInterface{
		name: interfaceName,
	}

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

// LoadConfig reads the given wireguard config file
// and configured the interface
func (wg *WireGuardInterface) LoadConfigFile(path string) error {
	config, err := ReadConfig(path)
	if err != nil {
		return errors.Wrap(err, "failed to load config file")
	}
	return wg.LoadConfig(config)
}

func (wg *WireGuardInterface) LoadConfig(config *ConfigFile) error {
	c, err := config.Config()
	if err != nil {
		return errors.Wrap(err, "invalid wireguard config")
	}

	wg.config = config

	client, err := wgctrl.New()
	if err != nil {
		return errors.Wrap(err, "failed to create wg client")
	}

	if err := client.ConfigureDevice(wg.Name(), *c); err != nil {
		return errors.Wrap(err, "failed to configure wireguard")
	}

	if err := wg.setIP(config.Interface.Address); err != nil {
		return errors.Wrap(err, "failed to set interface ip address")
	}

	if err := wg.Up(); err != nil {
		return errors.Wrap(err, "failed to bring interface up")
	}

	return nil
}

// Config returns the loaded wireguard config file
// can return nil if no config has been loaded
func (wg *WireGuardInterface) Config() *ConfigFile {
	return wg.config
}

// Device returns the wgtypes Device, this type contains
// runtime infomation about the wireguard interface
func (wg *WireGuardInterface) Device() (*wgtypes.Device, error) {
	c, err := wgctrl.New()
	if err != nil {
		return nil, err
	}
	return c.Device(wg.Name())
}

// Wait will return a channel that signals when the
// wireguard interface is stopped
func (wg *WireGuardInterface) Wait() chan struct{} {
	return wg.device.Wait()
}

// Close will stop and clean up both the wireguard
// interface and userspace configuration api
func (wg *WireGuardInterface) Close() error {
	if err := wg.uapi.Close(); err != nil {
		return err
	}
	wg.device.Close()
	return nil
}

// Name returns the real wireguard interface name e.g. wg0
func (wg *WireGuardInterface) Name() string {
	return wg.name
}
