// +build darwin

package wgconnect

// import (
// 	"os/exec"

// 	"github.com/pkg/errors"
// )

// func ifaceUp(name string, ip string) error {
// 	// bring the interface up
// 	cmd := exec.Command("ifconifg", name, "up")
// 	if err := cmd.Run(); err != nil {
// 		return errors.Wrap(err, "ifconfig up command failed")
// 	}

// 	// set it's ip address
// 	cmd = exec.Command("ifconfig", name, "inet", ip, ip, "alias")
// 	if err := cmd.Run(); err != nil {
// 		return errors.Wrap(err, "ifconfig inet command failed")
// 	}

// 	return nil
// }

// func ifaceDefaultRoute(name string) error {
// 	cmd := exec.Command("route", "-q", "-n", "add", "-inet", "0.0.0.0/0", "-interface", name)
// 	return cmd.Run()
// }
