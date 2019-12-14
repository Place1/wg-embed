package wgembed

import (
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	_ "golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

type KeyPair struct {
	PublicKey  string
	PrivateKey string
}

func NewKeyPair() KeyPair {
	key, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		logrus.Fatal(errors.Wrap(err, "failed to generate key"))
	}
	return KeyPair{
		PrivateKey: key.String(),
		PublicKey:  key.PublicKey().String(),
	}
}
