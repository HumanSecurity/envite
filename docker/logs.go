// Copyright 2024 HUMAN Security.
// Use of this source code is governed by a MIT style
// license that can be found in the LICENSE file.

package docker

import (
	"bufio"
	"context"
	"github.com/moby/moby/api/pkg/stdcopy"
	"github.com/moby/moby/client"
	"strings"
	"time"
)

type logHandler func(timestamp time.Time, text string, stream stdcopy.StdType) (stop bool)

// followLogs attaches to container's output
func followLogs(ctx context.Context, cli *client.Client, id string, handler logHandler) error {
	containerReader, err := cli.ContainerLogs(ctx, id, client.ContainerLogsOptions{
		ShowStdout: true,
		ShowStderr: true,
		Timestamps: true,
		Follow:     true,
	})
	if err != nil {
		return err
	}

	scanner := bufio.NewScanner(containerReader)
	for scanner.Scan() {
		var stop bool
		bytes := scanner.Bytes()
		if len(bytes) > 8 {
			t, text := extractMessageTime(string(bytes[8:]))
			stream := stdcopy.StdType(bytes[0])
			if stream == stdcopy.Systemerr {
				// docker system error, restart consume logs
				_ = containerReader.Close()
				return followLogs(ctx, cli, id, handler)
			}
			stop = handler(t, text, stream)
		} else {
			t, text := extractMessageTime(string(bytes))
			stop = handler(t, text, stdcopy.Stdout)
		}
		if stop {
			_ = containerReader.Close()
			return nil
		}
	}

	_ = containerReader.Close()
	return nil
}

func extractMessageTime(message string) (time.Time, string) {
	pos := strings.Index(message, " ")
	if pos > -1 {
		t, err := time.Parse(time.RFC3339Nano, message[:pos])
		if err == nil {
			return t, message[pos+1:]
		}
	}
	return time.Now(), message
}
