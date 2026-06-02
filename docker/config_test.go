// Copyright 2024 HUMAN Security.
// Use of this source code is governed by a MIT style
// license that can be found in the LICENSE file.

package docker

import (
	"net/netip"
	"testing"

	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/stretchr/testify/assert"
)

func TestContainerConfig(t *testing.T) {
	newSampleConfig := func() Config {
		return Config{
			Name:  "test-container",
			Image: "nginx:latest",
		}
	}

	network := &Network{
		KeepStoppedContainers: true,
	}

	imageCloneTag := "nginx:cloned"

	// Test when valid config
	config := newSampleConfig()
	runConfig, err := config.initialize(network, imageCloneTag)

	assert.NoError(t, err)
	assert.NotNil(t, runConfig)

	// Test when Name is empty
	config = newSampleConfig()
	config.Name = ""
	_, err = config.initialize(network, imageCloneTag)
	assert.Error(t, err)
	assert.EqualError(t, err, "invalid docker config - property name: cannot be empty")

	// Test when Image is empty
	config = newSampleConfig()
	config.Image = ""
	_, err = config.initialize(network, imageCloneTag)
	assert.Error(t, err)
	assert.EqualError(t, err, "invalid docker config - property image: cannot be empty")

	// Test when ConsoleSize has more than 2 elements
	config = newSampleConfig()
	config.ConsoleSize = []uint{1, 2, 3}
	_, err = config.initialize(network, imageCloneTag)
	assert.Error(t, err)
	assert.EqualError(t, err, "invalid docker config - property console_size: must have exactly two elements")

	// Test when Resources.KernelMemoryTCP is set
	config = newSampleConfig()
	config.Resources = &Resources{KernelMemoryTCP: 1}
	_, err = config.initialize(network, imageCloneTag)
	assert.Error(t, err)
	assert.EqualError(t, err, "invalid docker config - property resources.kernel_memory_tcp: is no longer supported by the Docker API and has no effect; remove it from the configuration")

	// Test when Waiters contain an invalid waiter type
	config = newSampleConfig()
	config.Waiters = []Waiter{
		{
			Type: "invalid",
		},
	}
	_, err = config.initialize(network, imageCloneTag)
	assert.Error(t, err)
	assert.EqualError(t, err, "invalid waiter type invalid")
}

func TestParsePlatforms(t *testing.T) {
	tests := []struct {
		name     string
		platform string
		want     []ocispec.Platform
		wantErr  bool
	}{
		{
			name:     "empty string returns nil",
			platform: "",
			want:     nil,
		},
		{
			name:     "single part is invalid",
			platform: "amd64",
			wantErr:  true,
		},
		{
			name:     "two parts are os and architecture",
			platform: "linux/amd64",
			want:     []ocispec.Platform{{OS: "linux", Architecture: "amd64"}},
		},
		{
			name:     "three parts are os, architecture and variant",
			platform: "linux/arm/v7",
			want:     []ocispec.Platform{{OS: "linux", Architecture: "arm", Variant: "v7"}},
		},
		{
			name:     "four parts are invalid",
			platform: "linux/arm/v7/extra",
			wantErr:  true,
		},
		{
			name:     "trailing slash is invalid",
			platform: "linux/",
			wantErr:  true,
		},
		{
			name:     "leading slash is invalid",
			platform: "/amd64",
			wantErr:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parsePlatforms(tt.platform)
			if tt.wantErr {
				assert.Error(t, err)
				assert.Nil(t, got)
				return
			}

			assert.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestParseDNSAddrs(t *testing.T) {
	tests := []struct {
		name    string
		addrs   []string
		want    []netip.Addr
		wantErr bool
	}{
		{
			name:  "nil input yields empty result",
			addrs: nil,
			want:  []netip.Addr{},
		},
		{
			name:  "valid IPv4 addresses",
			addrs: []string{"8.8.8.8", "1.1.1.1"},
			want:  []netip.Addr{netip.MustParseAddr("8.8.8.8"), netip.MustParseAddr("1.1.1.1")},
		},
		{
			name:  "valid IPv6 address",
			addrs: []string{"2001:4860:4860::8888"},
			want:  []netip.Addr{netip.MustParseAddr("2001:4860:4860::8888")},
		},
		{
			name:    "invalid address returns error",
			addrs:   []string{"8.8.8.8", "not-an-ip"},
			wantErr: true,
		},
		{
			name:    "out of range octet returns error",
			addrs:   []string{"999.999.999.999"},
			wantErr: true,
		},
		{
			name:    "empty address returns error",
			addrs:   []string{""},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseDNSAddrs(tt.addrs)
			if tt.wantErr {
				assert.Error(t, err)
				assert.Nil(t, got)
				return
			}

			assert.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}
