package wgembed

import (
	"reflect"
	"testing"
)

func TestReadConfig(t *testing.T) {
	type args struct {
		path string
	}
	tests := []struct {
		name    string
		args    args
		want    *ConfigFile
		wantErr bool
	}{
		{
			"dual-stack config file",
			args{"testdata/dualstack.conf"},
			&ConfigFile{
				Interface: IfaceConfig{
					PrivateKey: "wPNV/LaCgF5yx7bAotuxaaQ6jxsy1H7zs8LuNYzOXHQ=",
					Address:    []string{"10.44.0.1/24", "fd48:4c4:7aa9::1/64"},
					DNS:        []string{},
				},
				Peers: []PeerConfig{
					{PublicKey: "gysKSkCS/VeAyHIAVtf8B/sbQnEd5FYogtj7kO4d4zY=", AllowedIPs: []string{"10.44.0.2/32", "fd48:4c4:7aa9::2/128"}},
					{PublicKey: "bcEwHLic4PW9O3qECsbUWuD4PeU3NfRl5Cmiz+e/p3o=", AllowedIPs: []string{"10.44.0.3/32", "fd48:4c4:7aa9::3/128"}},
				},
				wgconfig: nil,
			},
			false,
		},
		{
			"IPv4-only config file",
			args{"testdata/ipv4-only.conf"},
			&ConfigFile{
				Interface: IfaceConfig{
					PrivateKey: "wPNV/LaCgF5yx7bAotuxaaQ6jxsy1H7zs8LuNYzOXHQ=",
					Address:    []string{"10.44.0.1/24"},
					DNS:        []string{},
				},
				Peers:    []PeerConfig{{PublicKey: "gysKSkCS/VeAyHIAVtf8B/sbQnEd5FYogtj7kO4d4zY=", AllowedIPs: []string{"10.44.0.2/32"}}},
				wgconfig: nil,
			},
			false,
		},
		{
			"IPv6-only config file",
			args{"testdata/ipv6-only.conf"},
			&ConfigFile{
				Interface: IfaceConfig{
					PrivateKey: "wPNV/LaCgF5yx7bAotuxaaQ6jxsy1H7zs8LuNYzOXHQ=",
					Address:    []string{"fd48:4c4:7aa9::1/64"},
					DNS:        []string{},
				},
				Peers:    []PeerConfig{{PublicKey: "gysKSkCS/VeAyHIAVtf8B/sbQnEd5FYogtj7kO4d4zY=", AllowedIPs: []string{"fd48:4c4:7aa9::2/128"}}},
				wgconfig: nil,
			},
			false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := tt.want.load(); err != nil {
				t.Errorf("wanted ConfigFile not valid")
			}

			got, err := ReadConfig(tt.args.path)
			if (err != nil) != tt.wantErr {
				t.Errorf("ReadConfig() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Error("ReadConfig() result does not match wanted config")
			}
		})
	}
}
