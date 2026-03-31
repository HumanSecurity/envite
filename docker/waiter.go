// Copyright 2024 HUMAN Security.
// Use of this source code is governed by a MIT style
// license that can be found in the LICENSE file.

package docker

import (
	"context"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/moby/moby/api/pkg/stdcopy"
	"github.com/moby/moby/client"
)

// WaitForLog creates a waiter for waiting until a specific string is found in the container logs.
func WaitForLog(s string) Waiter {
	return Waiter{
		Type:   WaiterTypeString,
		String: s,
	}
}

// WaitForLogRegex creates a waiter for waiting until a specific regular expression is matched in the container logs.
func WaitForLogRegex(regexp string) Waiter {
	return Waiter{
		Type:  WaiterTypeRegex,
		Regex: regexp,
	}
}

// WaitForDuration creates a waiter for waiting for a specific duration.
func WaitForDuration(duration string) Waiter {
	return Waiter{
		Type:     WaiterTypeDuration,
		Duration: duration,
	}
}

// waiterFunc is a function signature for the different types of waiters.
type waiterFunc func(ctx context.Context, cli *client.Client, containerID string, isNewContainer bool) error

// validateWaiter validates the provided waiter and returns the corresponding waiterFunc.
func validateWaiter(w Waiter) (waiterFunc, error) {
	switch w.Type {
	case WaiterTypeString:
		return func(ctx context.Context, cli *client.Client, containerID string, _ bool) error {
			var reached bool
			err := followLogs(ctx, cli, containerID, func(_ time.Time, text string, _ stdcopy.StdType) (stop bool) {
				reached = strings.Contains(text, w.String)
				return reached
			})
			if err != nil {
				return err
			}

			if reached {
				return nil
			}

			return ErrContainerStopped{without: fmt.Sprintf("reaching log '%s'", w.String)}
		}, nil
	case WaiterTypeRegex:
		re, err := regexp.Compile(w.Regex)
		if err != nil {
			return nil, fmt.Errorf("failed to compile regex: %w", err)
		}

		return func(ctx context.Context, cli *client.Client, containerID string, _ bool) error {
			var reached bool
			err := followLogs(ctx, cli, containerID, func(_ time.Time, text string, _ stdcopy.StdType) (stop bool) {
				reached = re.MatchString(text)
				return reached
			})
			if err != nil {
				return err
			}

			if reached {
				return nil
			}

			return ErrContainerStopped{without: fmt.Sprintf("reaching log regex '%s'", w.String)}
		}, nil
	case WaiterTypeDuration:
		d, err := time.ParseDuration(w.Duration)
		if err != nil {
			return nil, fmt.Errorf("failed to parse duration: %w", err)
		}

		return func(_ context.Context, _ *client.Client, _ string, isNewContainer bool) error {
			if !isNewContainer {
				return nil
			}

			time.Sleep(d)
			return nil
		}, nil
	}

	return nil, ErrInvalidWaiterType{Type: w.Type}
}

// ErrInvalidWaiterType represents an error for an invalid waiter type.
type ErrInvalidWaiterType struct {
	Type WaiterType
}

func (e ErrInvalidWaiterType) Error() string {
	return fmt.Sprintf("invalid waiter type %s", e.Type)
}

// ErrContainerStopped represents an error when the container stops without reaching the expected condition.
type ErrContainerStopped struct {
	without string
}

func (e ErrContainerStopped) Error() string {
	return fmt.Sprintf("container stopped without %s", e.without)
}
