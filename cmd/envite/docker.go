// Copyright 2024 HUMAN Security.
// Use of this source code is governed by a MIT style
// license that can be found in the LICENSE file.

package main

import (
	"encoding/json"
	"fmt"

	"github.com/moby/moby/client"
	"github.com/perimeterx/envite"
	"github.com/perimeterx/envite/docker"
)

// buildDocker constructs a Docker component based on the provided JSON configuration data.
// This function first ensures that a Docker network is initialized for the environment,
// then parses the JSON data into a Docker component configuration. If successful, it
// uses this configuration to create and return a new Docker component.
//
// Returns:
//   - An envite.Component of type docker.Component configured according to the provided data.
//   - An error if there is an issue initializing the Docker network, parsing the configuration data,
//     or creating the Docker component.
func buildDocker(data []byte, flags flagValues, envID string) (envite.Component, error) {
	err := initDockerNetwork(flags, envID)
	if err != nil {
		return nil, fmt.Errorf("could not init docker network: %w", err)
	}

	var config docker.Config
	err = json.Unmarshal(data, &config)
	if err != nil {
		return nil, fmt.Errorf("could not parse config: %w", err)
	}

	component, err := dockerNetwork.NewComponent(config)
	if err != nil {
		return nil, fmt.Errorf("could not create docker component: %w", err)
	}

	return component, nil
}

// dockerNetwork is a cached docker network to be used throughout the environment.
var dockerNetwork *docker.Network

// initDockerNetwork ensures that a cached Docker network is initialized for the environment.
// It uses the Docker client to connect to the Docker daemon and either finds an existing network
// with the provided ID or creates a new one. This network is then stored in a global variable for
// use by Docker components.
//
// This function is idempotent; it will not reinitialize the network if it has already been set.
// It returns error if there is a failure connecting to the Docker daemon, finding, or creating the Docker network.
func initDockerNetwork(flags flagValues, envID string) error {
	if dockerNetwork != nil {
		return nil
	}

	cli, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	if err != nil {
		return fmt.Errorf("could not connect to docker: %w", err)
	}

	var id string
	if flags.dockerNetworkID.exist {
		id = flags.dockerNetworkID.value
	}
	dockerNetwork, err = docker.NewNetwork(cli, id, envID)
	if err != nil {
		return fmt.Errorf("could not create a docker network: %w", err)
	}

	return nil
}
