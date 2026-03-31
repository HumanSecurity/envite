// Copyright 2024 HUMAN Security.
// Use of this source code is governed by a MIT style
// license that can be found in the LICENSE file.

package docker

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"math"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/containerd/errdefs"
	"github.com/moby/moby/api/pkg/stdcopy"
	"github.com/moby/moby/api/types/container"
	"github.com/moby/moby/api/types/jsonstream"
	"github.com/moby/moby/client"
	"github.com/perimeterx/envite"
)

// ComponentType is the type identifier for the Docker component.
const ComponentType = "docker component"

// Component represents a Docker container as a component in the ENVITE environment.
type Component struct {
	lock             sync.Mutex
	envID            string
	cli              *client.Client
	runtimeInfo      *RuntimeInfo
	config           Config
	runConfig        *runConfig
	network          *Network
	latestLogMessage time.Time
	containerName    string
	imageCloneTag    string
	status           atomic.Value
	env              *envite.Environment
	writer           *envite.Writer
}

// newComponent creates a new Docker component.
// docker components must be instantiated via a Network.
func newComponent(
	cli *client.Client,
	runtimeInfo *RuntimeInfo,
	envID string,
	network *Network,
	config Config,
) (*Component, error) {
	imageCloneTag := fmt.Sprintf("%s_%s", config.Image, envID)
	runConf, err := config.initialize(network, imageCloneTag)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize component config: %w", err)
	}

	containerName := fmt.Sprintf("%s_%s", envID, config.Name)
	network.configure(config, runConf, containerName)

	c := &Component{
		cli:           cli,
		runtimeInfo:   runtimeInfo,
		config:        config,
		envID:         envID,
		runConfig:     runConf,
		network:       network,
		containerName: containerName,
		imageCloneTag: imageCloneTag,
	}

	c.status.Store(envite.ComponentStatusStopped)

	return c, nil
}

func (c *Component) Type() string {
	return ComponentType
}

// AttachEnvironment attaches the environment, writer, and starts the log and starting status monitoring routines.
func (c *Component) AttachEnvironment(ctx context.Context, env *envite.Environment, writer *envite.Writer) error {
	c.env = env
	c.writer = writer

	cont, err := c.findContainer(ctx)
	if err != nil {
		return err
	}
	if cont == nil {
		return nil
	}

	go c.writeLogs(cont.ID)
	go c.monitorStartingStatus(cont.ID, false)

	return nil
}

// Prepare prepares the Docker component by executing any pre-startup actions specified in the configuration.
func (c *Component) Prepare(ctx context.Context) error {
	c.lock.Lock()
	defer c.lock.Unlock()

	for _, mount := range c.config.Mounts {
		if mount.OnMount != nil {
			mount.OnMount()
		}
	}

	err := c.pullImage(ctx)
	if err != nil {
		return err
	}

	// create a dedicated copy of the docker image to prevent
	// other environments running concurrently from removing our image.
	_, err = c.cli.ImageTag(ctx, client.ImageTagOptions{
		Source: c.config.Image,
		Target: c.imageCloneTag,
	})
	return err
}

// pullImage pulls the Docker image specified in the configuration.
func (c *Component) pullImage(ctx context.Context) error {
	if c.config.ImagePullOptions != nil && c.config.ImagePullOptions.Disabled {
		c.Writer().WriteString(fmt.Sprintf("image pull disabled"))
		return nil
	}

	opts, err := c.config.imagePullOptions()
	if err != nil {
		return err
	}

	result, err := c.cli.ImagePull(ctx, c.config.Image, opts)
	if err != nil {
		return err
	}
	defer result.Close()

	scanner := bufio.NewScanner(result)
	for scanner.Scan() {
		bytes := scanner.Bytes()
		msg := jsonstream.Message{}
		err = json.Unmarshal(bytes, &msg)
		if err != nil {
			return fmt.Errorf("failed to parse image pull output: %w", err)
		}

		if msg.Progress == nil || msg.Progress.Total == 0 {
			if msg.ID == "" {
				c.Writer().WriteString(msg.Status)
			} else {
				c.Writer().WriteString(fmt.Sprintf(
					"%s %s",
					c.Writer().Color.Cyan(msg.ID),
					msg.Status,
				))
			}
		} else {
			c.Writer().WriteString(fmt.Sprintf(
				"%s %s %d%%",
				c.Writer().Color.Cyan(msg.ID),
				msg.Status,
				int(math.Ceil(float64(msg.Progress.Current)/float64(msg.Progress.Total)*100)),
			))
		}
	}

	return nil
}

func (c *Component) Start(ctx context.Context) error {
	id, err := c.startContainer(ctx)
	if err != nil {
		return err
	}

	c.monitorStartingStatus(id, true)
	if c.runtimeInfo.NetworkLatency > 0 {
		time.Sleep(c.runtimeInfo.NetworkLatency)
	}
	return nil
}

func (c *Component) startContainer(ctx context.Context) (string, error) {
	c.lock.Lock()
	defer c.lock.Unlock()

	var id string
	res, err := c.cli.ContainerCreate(
		ctx,
		client.ContainerCreateOptions{
			Config:           c.runConfig.containerConfig,
			HostConfig:       c.runConfig.hostConfig,
			NetworkingConfig: c.runConfig.networkingConfig,
			Platform:         c.runConfig.platformConfig,
			Name:             c.containerName,
		},
	)
	if err == nil {
		id = res.ID
	} else if !errdefs.IsConflict(err) {
		return "", fmt.Errorf("failed to create container: %w", err)
	} else {
		cont, err := c.findContainer(ctx)
		if err != nil {
			return "", fmt.Errorf("failed to find container: %w", err)
		}

		id = cont.ID
	}

	_, err = c.cli.ContainerStart(context.Background(), id, client.ContainerStartOptions{})
	if err != nil {
		return "", fmt.Errorf("failed to start container: %w", err)
	}

	go c.writeLogs(id)
	return id, nil
}

func (c *Component) Stop(ctx context.Context) error {
	c.lock.Lock()
	defer c.lock.Unlock()

	cont, err := c.findContainer(ctx)
	if err != nil {
		return err
	}

	if cont == nil {
		return nil
	}

	_, err = c.cli.ContainerStop(ctx, cont.ID, client.ContainerStopOptions{})
	if err != nil {
		return err
	}

	_, err = c.cli.ContainerRemove(ctx, cont.ID, client.ContainerRemoveOptions{Force: true})
	if err != nil && !errdefs.IsNotFound(err) && !errdefs.IsConflict(err) {
		return err
	}

	c.status.Store(envite.ComponentStatusStopped)
	return nil
}

func (c *Component) Cleanup(ctx context.Context) error {
	c.lock.Lock()
	defer c.lock.Unlock()

	err := c.removeImage(ctx)
	if err != nil {
		return err
	}

	return c.network.delete(ctx, c)
}

func (c *Component) removeImage(ctx context.Context) error {
	_, err := c.cli.ImageRemove(ctx, c.imageCloneTag, client.ImageRemoveOptions{})
	if err != nil && !strings.Contains(err.Error(), "reference does not exist") && !strings.Contains(err.Error(), "No such image") {
		return err
	}

	if c.config.ImagePullOptions != nil && c.config.ImagePullOptions.Disabled {
		c.Writer().WriteString(fmt.Sprintf("image remove disabled"))
		return nil
	}

	_, err = c.cli.ImageRemove(ctx, c.config.Image, client.ImageRemoveOptions{})
	if err != nil && !errdefs.IsNotFound(err) {
		return err
	}

	return nil
}

func (c *Component) Status(context.Context) (envite.ComponentStatus, error) {
	status := c.status.Load().(envite.ComponentStatus)

	if status == envite.ComponentStatusRunning {
		// check if container stopped
		cont, err := c.findContainer(context.Background())
		if err != nil {
			return "", fmt.Errorf("failed to find container: %w", err)
		}

		if cont == nil || cont.State != "running" {
			status = envite.ComponentStatusStopped
			c.status.Store(envite.ComponentStatusStopped)
		}
	}

	return status, nil
}

func (c *Component) monitorStartingStatus(containerID string, isNewContainer bool) {
	c.status.Store(envite.ComponentStatusStarting)
	for _, waiter := range c.runConfig.waiters {
		err := waiter(context.Background(), c.cli, containerID, isNewContainer)
		if err != nil {
			// container might have been manually stopped while we waited
			c.lock.Lock()
			if c.status.Load() == envite.ComponentStatusStarting {
				c.status.Store(envite.ComponentStatusFailed)
			}
			c.lock.Unlock()
			return
		}
	}
	c.status.Store(envite.ComponentStatusRunning)
}

func (c *Component) Config() any {
	return c.config
}

// Exec executes a command in the Docker container.
func (c *Component) Exec(ctx context.Context, cmd []string) (int, error) {
	cont, err := c.findContainer(ctx)
	if err != nil {
		return 0, fmt.Errorf("failed to find container: %w", err)
	}

	c.Writer().WriteString(c.Writer().Color.Cyan(fmt.Sprintf("executing: %s", strings.Join(cmd, " "))))
	response, err := c.cli.ExecCreate(ctx, cont.ID, client.ExecCreateOptions{
		Cmd:          cmd,
		AttachStdout: true,
		AttachStderr: true,
	})
	if err != nil {
		return 0, fmt.Errorf("failed to create exec: %w", err)
	}

	hijack, err := c.cli.ExecAttach(ctx, response.ID, client.ExecAttachOptions{})
	if err != nil {
		return 0, fmt.Errorf("failed to attach exec: %w", err)
	}

	scanner := bufio.NewScanner(hijack.Reader)
	for scanner.Scan() {
		c.Writer().WriteString(c.Writer().Color.Cyan(fmt.Sprintf("exec output: %s", scanner.Text())))
	}

	hijack.Close()

	execResp, err := c.cli.ExecInspect(ctx, response.ID, client.ExecInspectOptions{})
	if err != nil {
		return 0, fmt.Errorf("failed to inspect exec: %w", err)
	}

	c.Writer().WriteString(c.Writer().Color.Cyan(fmt.Sprintf("exit code: %d", execResp.ExitCode)))
	return execResp.ExitCode, nil
}

func (c *Component) findContainer(ctx context.Context) (*container.Summary, error) {
	result, err := c.cli.ContainerList(ctx, client.ContainerListOptions{
		All:     true,
		Filters: make(client.Filters).Add("name", c.containerName),
	})
	if err != nil {
		return nil, fmt.Errorf("failed to list containers: %w", err)
	}

	for _, co := range result.Items {
		if len(co.Names) > 0 && co.Names[0][1:] == c.containerName {
			return &co, nil
		}
	}

	return nil, nil
}

func (c *Component) writeLogs(id string) {
	err := followLogs(
		context.Background(),
		c.cli,
		id,
		func(timestamp time.Time, text string, stream stdcopy.StdType) (stop bool) {
			if timestamp.Before(c.latestLogMessage) {
				return false
			}

			if stream == stdcopy.Stderr {
				text = c.Writer().Color.Red(text)
			}

			c.latestLogMessage = timestamp
			c.Writer().WriteStringWithTime(timestamp, text)
			return false
		},
	)
	if err != nil {
		c.Logger()(envite.LogLevelError, "could not read container logs for "+c.containerName)
	}
}

// Host returns the hostname of the Docker component.
func (c *Component) Host() string {
	return c.runConfig.hostname
}

// ContainerName returns the name of the Docker container.
func (c *Component) ContainerName() string {
	return c.containerName
}

// Writer returns the writer associated with the Docker component.
func (c *Component) Writer() *envite.Writer {
	return c.writer
}

// Logger returns the logger associated with the Docker component.
func (c *Component) Logger() envite.Logger {
	return c.env.Logger
}
