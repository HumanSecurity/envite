package docker

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/moby/moby/client"
)

// RuntimeInfo contains information about a runtime type
type RuntimeInfo struct {
	// Runtime is the name of the runtime
	Runtime string
	// InternalHostname is the hostname to use for the docker daemon
	InternalHostname string
	// NetworkLatency some runtimes have a slight latency before network is ready when starting a container
	NetworkLatency time.Duration
}

// ExtractRuntimeInfo detects the Docker daemon implementation for the given client
func ExtractRuntimeInfo(ctx context.Context, cli *client.Client) (*RuntimeInfo, error) {
	infoResult, err := cli.Info(ctx, client.InfoOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to get docker info: %w", err)
	}

	info := infoResult.Info
	name := strings.ToLower(info.Name)
	serverVersion := strings.ToLower(info.ServerVersion)

	// Check for specific runtime indicators
	if strings.Contains(name, "colima") || strings.Contains(serverVersion, "colima") {
		return &RuntimeInfo{
			Runtime:          "Colima",
			InternalHostname: "host.lima.internal",
			NetworkLatency:   time.Second * 3,
		}, nil
	}

	if strings.Contains(name, "podman") || strings.Contains(serverVersion, "podman") {
		return &RuntimeInfo{
			Runtime:          "Podman",
			InternalHostname: "host.containers.internal",
		}, nil
	}

	if strings.Contains(name, "rancher") || strings.Contains(serverVersion, "rancher") {
		return &RuntimeInfo{
			Runtime:          "Rancher Desktop",
			InternalHostname: "host.docker.internal",
		}, nil
	}

	if strings.Contains(name, "lima") || strings.Contains(serverVersion, "lima") {
		return &RuntimeInfo{
			Runtime:          "Lima",
			InternalHostname: "host.lima.internal",
		}, nil
	}

	if strings.Contains(name, "orbstack") || strings.Contains(serverVersion, "orbstack") {
		return &RuntimeInfo{
			Runtime:          "OrbStack",
			InternalHostname: "host.docker.internal",
		}, nil
	}

	if strings.Contains(name, "minikube") || strings.Contains(serverVersion, "minikube") {
		return &RuntimeInfo{
			Runtime:          "Minikube",
			InternalHostname: "host.minikube.internal",
		}, nil
	}

	if strings.Contains(name, "containerd") || strings.Contains(serverVersion, "containerd") {
		return &RuntimeInfo{
			Runtime:          "ContainerD",
			InternalHostname: "host.docker.internal",
		}, nil
	}

	if strings.Contains(name, "finch") || strings.Contains(serverVersion, "finch") {
		return &RuntimeInfo{
			Runtime:          "Finch",
			InternalHostname: "host.docker.internal",
		}, nil
	}

	// Default to Docker Desktop for unknown runtimes
	return &RuntimeInfo{
		Runtime:          "Docker Desktop",
		InternalHostname: "host.docker.internal",
	}, nil
}
