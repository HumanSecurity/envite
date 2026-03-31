// Copyright 2024 HUMAN Security.
// Use of this source code is governed by a MIT style
// license that can be found in the LICENSE file.

package docker

import (
	"context"
	"fmt"
	"net/netip"
	"os"
	"time"

	"github.com/docker/go-units"
	"github.com/moby/moby/api/types/blkiodev"
	"github.com/moby/moby/api/types/container"
	"github.com/moby/moby/api/types/mount"
	"github.com/moby/moby/api/types/network"
	"github.com/moby/moby/api/types/strslice"
	"github.com/moby/moby/client"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"gopkg.in/yaml.v3"
)

// Config represents Docker Component configuration
type Config struct {
	// Name - the name of the container. Name cannot be empty.
	Name string `json:"name"`

	// Env - environment variables for the container
	Env map[string]string `json:"env"`

	// Ports - list of ports to expose
	// we don't map internal ports to a different external ports since it won't be consistent
	// for open network situations used in local development powered by docker network mode "host"
	Ports []Port `json:"ports,omitempty"`

	// Waiters - list of waiters. A waiter is a function responsible for waiting for healthy status
	// of the container before finishing the container start process
	Waiters []Waiter `json:"waiters,omitempty"`

	// ImagePullOptions - options for pulling the container image
	ImagePullOptions *ImagePullOptions `json:"image_pull_options,omitempty"`

	// Hostname - used for https://github.com/moby/moby/blob/v24.0.6/api/types/container/config.go#L71
	Hostname string `json:"hostname,omitempty"`

	// Domainname - used for https://github.com/moby/moby/blob/v24.0.6/api/types/container/config.go#L72
	Domainname string `json:"domainname,omitempty"`

	// User - used for https://github.com/moby/moby/blob/v24.0.6/api/types/container/config.go#L73
	User string `json:"user,omitempty"`

	// AttachStdin - used for https://github.com/moby/moby/blob/v24.0.6/api/types/container/config.go#L74
	AttachStdin bool `json:"attach_stdin,omitempty"`

	// AttachStdout - used for https://github.com/moby/moby/blob/v24.0.6/api/types/container/config.go#L75
	AttachStdout bool `json:"attach_stdout,omitempty"`

	// AttachStderr - used for https://github.com/moby/moby/blob/v24.0.6/api/types/container/config.go#L76
	AttachStderr bool `json:"attach_stderr,omitempty"`

	// Tty - used for https://github.com/moby/moby/blob/v24.0.6/api/types/container/config.go#L78
	Tty bool `json:"tty,omitempty"`

	// OpenStdin - used for https://github.com/moby/moby/blob/v24.0.6/api/types/container/config.go#L79
	OpenStdin bool `json:"open_stdin,omitempty"`

	// StdinOnce - used for https://github.com/moby/moby/blob/v24.0.6/api/types/container/config.go#L80
	StdinOnce bool `json:"stdin_once,omitempty"`

	// Cmd - used for https://github.com/moby/moby/blob/v24.0.6/api/types/container/config.go#L82
	Cmd StrSlice `json:"cmd,omitempty"`

	// Healthcheck - used for https://github.com/moby/moby/blob/v24.0.6/api/types/container/config.go#L83
	Healthcheck *Healthcheck `json:"healthcheck,omitempty"`

	// ArgsEscaped - used for https://github.com/moby/moby/blob/v24.0.6/api/types/container/config.go#L84
	ArgsEscaped bool `json:"args_escaped,omitempty"`

	// Image - used for https://github.com/moby/moby/blob/v24.0.6/api/types/container/config.go#L85
	// Image cannot be empty
	Image string `json:"image,omitempty"`

	// Volumes - used for https://github.com/moby/moby/blob/v24.0.6/api/types/container/config.go#L86
	Volumes map[string]struct{} `json:"volumes,omitempty"`

	// WorkingDir - used for https://github.com/moby/moby/blob/v24.0.6/api/types/container/config.go#L87
	WorkingDir string `json:"working_dir,omitempty"`

	// Entrypoint - used for https://github.com/moby/moby/blob/v24.0.6/api/types/container/config.go#L88
	Entrypoint StrSlice `json:"entrypoint,omitempty"`

	// NetworkDisabled - used for https://github.com/moby/moby/blob/v24.0.6/api/types/container/config.go#L89
	NetworkDisabled bool `json:"network_disabled,omitempty"`

	// MacAddress - DEPRECATED in v29: MAC address is now set via network endpoint settings
	// This field is kept for backwards compatibility but is no longer used
	MacAddress string `json:"mac_address,omitempty"`

	// OnBuild - used for https://github.com/moby/moby/blob/v24.0.6/api/types/container/config.go#L91
	OnBuild []string `json:"on_build,omitempty"`

	// Labels - used for https://github.com/moby/moby/blob/v24.0.6/api/types/container/config.go#L92
	Labels map[string]string `json:"labels,omitempty"`

	// StopSignal - used for https://github.com/moby/moby/blob/v24.0.6/api/types/container/config.go#L93
	StopSignal string `json:"stop_signal,omitempty"`

	// StopTimeout - used for https://github.com/moby/moby/blob/v24.0.6/api/types/container/config.go#L94
	StopTimeout *int `json:"stop_timeout,omitempty"`

	// Shell - used for https://github.com/moby/moby/blob/v24.0.6/api/types/container/config.go#L95
	Shell StrSlice `json:"shell,omitempty"`

	// Binds - used for https://github.com/moby/moby/blob/v24.0.6/api/types/container/hostconfig.go#L381
	Binds []string `json:"binds,omitempty"`

	// ContainerIDFile - used for https://github.com/moby/moby/blob/v24.0.6/api/types/container/hostconfig.go#L382
	ContainerIDFile string `json:"container_id_file,omitempty"`

	// LogConfig - used for https://github.com/moby/moby/blob/v24.0.6/api/types/container/hostconfig.go#L383
	LogConfig *LogConfig `json:"log_config,omitempty"`

	// RestartPolicy - used for https://github.com/moby/moby/blob/v24.0.6/api/types/container/hostconfig.go#L386
	RestartPolicy *RestartPolicy `json:"restart_policy,omitempty"`

	// VolumeDriver - used for https://github.com/moby/moby/blob/v24.0.6/api/types/container/hostconfig.go#L388
	VolumeDriver string `json:"volume_driver,omitempty"`

	// VolumesFrom - used for https://github.com/moby/moby/blob/v24.0.6/api/types/container/hostconfig.go#L389
	VolumesFrom []string `json:"volumes_from,omitempty"`

	// ConsoleSize - used for https://github.com/moby/moby/blob/v24.0.6/api/types/container/hostconfig.go#L390
	ConsoleSize []uint `json:"console_size,omitempty"`

	// Annotations - used for https://github.com/moby/moby/blob/v24.0.6/api/types/container/hostconfig.go#L391
	Annotations map[string]string `json:"annotations,omitempty"`

	// CapAdd - used for https://github.com/moby/moby/blob/v24.0.6/api/types/container/hostconfig.go#L394
	CapAdd StrSlice `json:"cap_add,omitempty"`

	// CapDrop - used for https://github.com/moby/moby/blob/v24.0.6/api/types/container/hostconfig.go#L395
	CapDrop StrSlice `json:"cap_drop,omitempty"`

	// CgroupnsMode - used for https://github.com/moby/moby/blob/v24.0.6/api/types/container/hostconfig.go#L396
	CgroupnsMode container.CgroupnsMode `json:"cgroupns_mode,omitempty"`

	// DNS - used for https://github.com/moby/moby/blob/v24.0.6/api/types/container/hostconfig.go#L397
	DNS []string `json:"dns,omitempty"`

	// DNSOptions - used for https://github.com/moby/moby/blob/v24.0.6/api/types/container/hostconfig.go#L398
	DNSOptions []string `json:"dns_options,omitempty"`

	// DNSSearch - used for https://github.com/moby/moby/blob/v24.0.6/api/types/container/hostconfig.go#L399
	DNSSearch []string `json:"dns_search,omitempty"`

	// ExtraHosts - used for https://github.com/moby/moby/blob/v24.0.6/api/types/container/hostconfig.go#L400
	ExtraHosts []string `json:"extra_hosts,omitempty"`

	// GroupAdd - used for https://github.com/moby/moby/blob/v24.0.6/api/types/container/hostconfig.go#L401
	GroupAdd []string `json:"group_add,omitempty"`

	// IpcMode - used for https://github.com/moby/moby/blob/v24.0.6/api/types/container/hostconfig.go#L402
	IpcMode container.IpcMode `json:"ipc_mode,omitempty"`

	// Cgroup - used for https://github.com/moby/moby/blob/v24.0.6/api/types/container/hostconfig.go#L403
	Cgroup container.CgroupSpec `json:"cgroup,omitempty"`

	// Links - used for https://github.com/moby/moby/blob/v24.0.6/api/types/container/hostconfig.go#L404
	Links []string `json:"links,omitempty"`

	// OomScoreAdj - used for https://github.com/moby/moby/blob/v24.0.6/api/types/container/hostconfig.go#L405
	OomScoreAdj int `json:"oom_score_adj,omitempty"`

	// PidMode - used for https://github.com/moby/moby/blob/v24.0.6/api/types/container/hostconfig.go#L406
	PidMode container.PidMode `json:"pid_mode,omitempty"`

	// Privileged - used for https://github.com/moby/moby/blob/v24.0.6/api/types/container/hostconfig.go#L407
	Privileged bool `json:"privileged,omitempty"`

	// PublishAllPorts - used for https://github.com/moby/moby/blob/v24.0.6/api/types/container/hostconfig.go#L408
	PublishAllPorts bool `json:"publish_all_ports,omitempty"`

	// ReadonlyRootfs - used for https://github.com/moby/moby/blob/v24.0.6/api/types/container/hostconfig.go#L409
	ReadonlyRootfs bool `json:"readonly_rootfs,omitempty"`

	// SecurityOpt - used for https://github.com/moby/moby/blob/v24.0.6/api/types/container/hostconfig.go#L410
	SecurityOpt []string `json:"security_opt,omitempty"`

	// StorageOpt - used for https://github.com/moby/moby/blob/v24.0.6/api/types/container/hostconfig.go#L411
	StorageOpt map[string]string `json:"storage_opt,omitempty"`

	// Tmpfs - used for https://github.com/moby/moby/blob/v24.0.6/api/types/container/hostconfig.go#L412
	Tmpfs map[string]string `json:"tmpfs,omitempty"`

	// UTSMode - used for https://github.com/moby/moby/blob/v24.0.6/api/types/container/hostconfig.go#L413
	UTSMode container.UTSMode `json:"uts_mode,omitempty"`

	// UsernsMode - used for https://github.com/moby/moby/blob/v24.0.6/api/types/container/hostconfig.go#L414
	UsernsMode container.UsernsMode `json:"userns_mode,omitempty"`

	// ShmSize - used for https://github.com/moby/moby/blob/v24.0.6/api/types/container/hostconfig.go#L415
	ShmSize int64 `json:"shm_size,omitempty"`

	// Sysctls - used for https://github.com/moby/moby/blob/v24.0.6/api/types/container/hostconfig.go#L416
	Sysctls map[string]string `json:"sysctls,omitempty"`

	// Runtime - used for https://github.com/moby/moby/blob/v24.0.6/api/types/container/hostconfig.go#L417
	Runtime string `json:"runtime,omitempty"`

	// Isolation - used for https://github.com/moby/moby/blob/v24.0.6/api/types/container/hostconfig.go#L420
	Isolation container.Isolation `json:"isolation,omitempty"`

	// Resources - used for https://github.com/moby/moby/blob/v24.0.6/api/types/container/hostconfig.go#L423
	Resources *Resources `json:"resources,omitempty"`

	// Mounts - used for https://github.com/moby/moby/blob/v24.0.6/api/types/container/hostconfig.go#L426
	Mounts []Mount `json:"mounts,omitempty"`

	// MaskedPaths - used for https://github.com/moby/moby/blob/v24.0.6/api/types/container/hostconfig.go#L429
	MaskedPaths []string `json:"masked_paths,omitempty"`

	// ReadonlyPaths - used for https://github.com/moby/moby/blob/v24.0.6/api/types/container/hostconfig.go#L432
	ReadonlyPaths []string `json:"readonly_paths,omitempty"`

	// Init - used for https://github.com/moby/moby/blob/v24.0.6/api/types/container/hostconfig.go#L435
	Init *bool `json:"init,omitempty"`

	// PlatformConfig describes the platform which the image in the manifest runs on
	PlatformConfig *PlatformConfig `json:"platform_config,omitempty"`
}

// Port represents a single port to expose
type Port struct {
	// Port to expose
	Port string `json:"port,omitempty"`

	// Protocol to use - "tcp"/"udp". can be left empty, the default value in this case will be "tcp"
	Protocol string `json:"protocol,omitempty"`
}

// Waiter represents a Docker component waiter config.
// A Waiter waits for a docker component to meet a certain condition before finishing its startup.
type Waiter struct {
	// Type - WaiterType type to use
	Type WaiterType `json:"type,omitempty"`

	// String - only for Type == "string"
	// the string value to wait for
	String string `json:"string,omitempty"`

	// Regex - only for Type == "regex"
	// the regex value to wait for
	// compiled to a go regexp.Regexp using re2 syntax
	Regex string `json:"regex,omitempty"`

	// Duration - only for Type == "duration"
	// the duration to wait
	// parsed as a go duration using time.ParseDuration
	Duration string `json:"duration,omitempty"`
}

// WaiterType represents a type of Docker component waiter.
type WaiterType string

const (
	// WaiterTypeString - waits for a log line to contain a string value
	WaiterTypeString WaiterType = "string"

	// WaiterTypeRegex - waits for a log line to match a regex
	WaiterTypeRegex WaiterType = "regex"

	// WaiterTypeDuration - waits for a certain amount of time
	WaiterTypeDuration WaiterType = "duration"
)

// ImagePullOptions allow specifying Docker image pull related configs.
type ImagePullOptions struct {
	// Disabled allow disabling image pull/remove
	// this is useful when the image already exists on the machine and we want it to remain after cleanup
	Disabled bool `json:"disabled,omitempty"`

	// All - used for https://github.com/moby/moby/blob/v24.0.6/api/types/client.go#L279
	All bool `json:"all,omitempty"`

	// RegistryAuth - used for https://github.com/moby/moby/blob/v24.0.6/api/types/client.go#L280
	// only available when RegistryAuthFunc is not set
	RegistryAuth string `json:"registry_auth,omitempty"`

	// PrivilegeFunc - used for https://github.com/moby/moby/blob/v24.0.6/api/types/client.go#L281
	// available only via code, not available in config files
	// Updated signature for v29 - now takes context.Context
	PrivilegeFunc func() (string, error) `json:"-"`

	// Platform - used for https://github.com/moby/moby/blob/v24.0.6/api/types/client.go#L282
	Platform string `json:"platform,omitempty"`

	// a lazy load function for the RegistryAuth
	// available only via code, not available in config files
	// used when loading the auth file take a long time, and you want to avoid loading it when it's not needed
	RegistryAuthFunc func() (string, error) `json:"-"`
}

// Healthcheck allow specifying Docker healthcheck config.
type Healthcheck struct {
	// Test - used for https://github.com/moby/moby/blob/v24.0.6/api/types/container/config.go#L44
	Test []string `json:"test,omitempty"`

	// Interval - used for https://github.com/moby/moby/blob/v24.0.6/api/types/container/config.go#L47
	Interval time.Duration `json:"interval,omitempty"`

	// Timeout - used for https://github.com/moby/moby/blob/v24.0.6/api/types/container/config.go#L48
	Timeout time.Duration `json:"timeout,omitempty"`

	// StartPeriod - used for https://github.com/moby/moby/blob/v24.0.6/api/types/container/config.go#L49
	StartPeriod time.Duration `json:"start_period,omitempty"`

	// Retries - used for https://github.com/moby/moby/blob/v24.0.6/api/types/container/config.go#L53
	Retries int `json:"retries,omitempty"`
}

// LogConfig allow specifying Docker logs config.
type LogConfig struct {
	// Type - used for https://github.com/moby/moby/blob/v24.0.6/api/types/container/hostconfig.go#L321
	Type string `json:"type,omitempty"`

	// Config - used for https://github.com/moby/moby/blob/v24.0.6/api/types/container/hostconfig.go#L322
	Config map[string]string `json:"config,omitempty"`
}

// RestartPolicy allow specifying Docker restart policy config.
type RestartPolicy struct {
	// Name - used for https://github.com/moby/moby/blob/v24.0.6/api/types/container/hostconfig.go#L274
	Name string

	// MaximumRetryCount - used for https://github.com/moby/moby/blob/v24.0.6/api/types/container/hostconfig.go#L275
	MaximumRetryCount int
}

// Resources allow specifying Docker resources config.
type Resources struct {
	// CPUShares - used for https://github.com/moby/moby/blob/v24.0.6/api/types/container/hostconfig.go#L328
	CPUShares int64 `json:"cpu_shares,omitempty"`

	// Memory - used for https://github.com/moby/moby/blob/v24.0.6/api/types/container/hostconfig.go#L329
	Memory int64 `json:"memory,omitempty"`

	// NanoCPUs - used for https://github.com/moby/moby/blob/v24.0.6/api/types/container/hostconfig.go#L330
	NanoCPUs int64 `json:"nano_cp_us,omitempty"`

	// CgroupParent - used for https://github.com/moby/moby/blob/v24.0.6/api/types/container/hostconfig.go#L333
	CgroupParent string `json:"cgroup_parent,omitempty"`

	// BlkioWeight - used for https://github.com/moby/moby/blob/v24.0.6/api/types/container/hostconfig.go#L334
	BlkioWeight uint16 `json:"blkio_weight,omitempty"`

	// BlkioWeightDevice - used for https://github.com/moby/moby/blob/v24.0.6/api/types/container/hostconfig.go#L335
	BlkioWeightDevice []WeightDevice `json:"blkio_weight_device,omitempty"`

	// BlkioDeviceReadBps - used for https://github.com/moby/moby/blob/v24.0.6/api/types/container/hostconfig.go#L336
	BlkioDeviceReadBps []ThrottleDevice `json:"blkio_device_read_bps,omitempty"`

	// BlkioDeviceWriteBps - used for https://github.com/moby/moby/blob/v24.0.6/api/types/container/hostconfig.go#L337
	BlkioDeviceWriteBps []ThrottleDevice `json:"blkio_device_write_bps,omitempty"`

	// BlkioDeviceReadIOps - used for https://github.com/moby/moby/blob/v24.0.6/api/types/container/hostconfig.go#L338
	BlkioDeviceReadIOps []ThrottleDevice `json:"blkio_device_read_i_ops,omitempty"`

	// BlkioDeviceWriteIOps - used for https://github.com/moby/moby/blob/v24.0.6/api/types/container/hostconfig.go#L339
	BlkioDeviceWriteIOps []ThrottleDevice `json:"blkio_device_write_i_ops,omitempty"`

	// CPUPeriod - used for https://github.com/moby/moby/blob/v24.0.6/api/types/container/hostconfig.go#L340
	CPUPeriod int64 `json:"cpu_period,omitempty"`

	// CPUQuota - used for https://github.com/moby/moby/blob/v24.0.6/api/types/container/hostconfig.go#L341
	CPUQuota int64 `json:"cpu_quota,omitempty"`

	// CPURealtimePeriod - used for https://github.com/moby/moby/blob/v24.0.6/api/types/container/hostconfig.go#L342
	CPURealtimePeriod int64 `json:"cpu_realtime_period,omitempty"`

	// CPURealtimeRuntime - used for https://github.com/moby/moby/blob/v24.0.6/api/types/container/hostconfig.go#L343
	CPURealtimeRuntime int64 `json:"cpu_realtime_runtime,omitempty"`

	// CpusetCpus - used for https://github.com/moby/moby/blob/v24.0.6/api/types/container/hostconfig.go#L344
	CpusetCpus string `json:"cpuset_cpus,omitempty"`

	// CpusetMems - used for https://github.com/moby/moby/blob/v24.0.6/api/types/container/hostconfig.go#L345
	CpusetMems string `json:"cpuset_mems,omitempty"`

	// Devices - used for https://github.com/moby/moby/blob/v24.0.6/api/types/container/hostconfig.go#L346
	Devices []DeviceMapping `json:"devices,omitempty"`

	// DeviceCgroupRules - used for https://github.com/moby/moby/blob/v24.0.6/api/types/container/hostconfig.go#L347
	DeviceCgroupRules []string `json:"device_cgroup_rules,omitempty"`

	// DeviceRequests - used for https://github.com/moby/moby/blob/v24.0.6/api/types/container/hostconfig.go#L348
	DeviceRequests []DeviceRequest `json:"device_requests,omitempty"`

	// KernelMemoryTCP - DEPRECATED: This field has been removed in Docker v29
	// This field is kept for backwards compatibility but is no longer used
	KernelMemoryTCP int64 `json:"kernel_memory_tcp,omitempty"`

	// MemoryReservation - used for https://github.com/moby/moby/blob/v24.0.6/api/types/container/hostconfig.go#L354
	MemoryReservation int64 `json:"memory_reservation,omitempty"`

	// MemorySwap - used for https://github.com/moby/moby/blob/v24.0.6/api/types/container/hostconfig.go#L355
	MemorySwap int64 `json:"memory_swap,omitempty"`

	// MemorySwappiness - used for https://github.com/moby/moby/blob/v24.0.6/api/types/container/hostconfig.go#L356
	MemorySwappiness *int64 `json:"memory_swappiness,omitempty"`

	// OomKillDisable - used for https://github.com/moby/moby/blob/v24.0.6/api/types/container/hostconfig.go#L357
	OomKillDisable *bool `json:"oom_kill_disable,omitempty"`

	// PidsLimit - used for https://github.com/moby/moby/blob/v24.0.6/api/types/container/hostconfig.go#L358
	PidsLimit *int64 `json:"pids_limit,omitempty"`

	// Ulimits - used for https://github.com/moby/moby/blob/v24.0.6/api/types/container/hostconfig.go#L359
	Ulimits []Ulimit `json:"ulimits,omitempty"`

	// CPUCount - used for https://github.com/moby/moby/blob/v24.0.6/api/types/container/hostconfig.go#L362
	CPUCount int64 `json:"cpu_count,omitempty"`

	// CPUPercent - used for https://github.com/moby/moby/blob/v24.0.6/api/types/container/hostconfig.go#L363
	CPUPercent int64 `json:"cpu_percent,omitempty"`

	// IOMaximumIOps - used for https://github.com/moby/moby/blob/v24.0.6/api/types/container/hostconfig.go#L364
	IOMaximumIOps uint64 `json:"io_maximum_i_ops,omitempty"`

	// IOMaximumBandwidth - used for https://github.com/moby/moby/blob/v24.0.6/api/types/container/hostconfig.go#L365
	IOMaximumBandwidth uint64 `json:"io_maximum_bandwidth,omitempty"`
}

// WeightDevice allow specifying Docker weight device config.
type WeightDevice struct {
	// Path - used for https://github.com/moby/moby/blob/v24.0.6/api/types/blkiodev/blkio.go#L7
	Path string `json:"path,omitempty"`

	// Weight - used for https://github.com/moby/moby/blob/v24.0.6/api/types/blkiodev/blkio.go#L8
	Weight uint16 `json:"weight,omitempty"`
}

// ThrottleDevice allow specifying Docker throttle device config.
type ThrottleDevice struct {
	// Path - used for https://github.com/moby/moby/blob/v24.0.6/api/types/blkiodev/blkio.go#L17
	Path string `json:"path,omitempty"`

	// Rate - used for https://github.com/moby/moby/blob/v24.0.6/api/types/blkiodev/blkio.go#L18
	Rate uint64 `json:"rate,omitempty"`
}

// DeviceMapping allow specifying Docker device mapping config.
type DeviceMapping struct {
	// PathOnHost - used for https://github.com/moby/moby/blob/v24.0.6/api/types/container/hostconfig.go#L267
	PathOnHost string `json:"path_on_host,omitempty"`

	// PathInContainer - used for https://github.com/moby/moby/blob/v24.0.6/api/types/container/hostconfig.go#L268
	PathInContainer string `json:"path_in_container,omitempty"`

	// CgroupPermissions - used for https://github.com/moby/moby/blob/v24.0.6/api/types/container/hostconfig.go#L269
	CgroupPermissions string `json:"cgroup_permissions,omitempty"`
}

// DeviceRequest allow specifying Docker device request config.
type DeviceRequest struct {
	// Driver - used for https://github.com/moby/moby/blob/v24.0.6/api/types/container/hostconfig.go#L258
	Driver string `json:"driver,omitempty"`

	// Count - used for https://github.com/moby/moby/blob/v24.0.6/api/types/container/hostconfig.go#L259
	Count int `json:"count,omitempty"`

	// DeviceIDs - used for https://github.com/moby/moby/blob/v24.0.6/api/types/container/hostconfig.go#L260
	DeviceIDs []string `json:"device_ids,omitempty"`

	// Capabilities - used for https://github.com/moby/moby/blob/v24.0.6/api/types/container/hostconfig.go#L261
	Capabilities [][]string `json:"capabilities,omitempty"`

	// Options - used for https://github.com/moby/moby/blob/v24.0.6/api/types/container/hostconfig.go#L262
	Options map[string]string `json:"options,omitempty"`
}

// Ulimit allow specifying Docker ulimit config.
type Ulimit struct {
	// Name - used for https://github.com/docker/go-units/blob/master/ulimit.go#L11
	Name string `json:"name,omitempty"`

	// Hard - used for https://github.com/docker/go-units/blob/master/ulimit.go#L12
	Hard int64 `json:"hard,omitempty"`

	// Soft - used for https://github.com/docker/go-units/blob/master/ulimit.go#L13
	Soft int64 `json:"soft,omitempty"`
}

// Mount allow specifying a Docker mount.
type Mount struct {
	// Type - used for https://github.com/moby/moby/blob/v24.0.6/api/types/mount/mount.go#L26
	Type mount.Type `json:"type,omitempty"`

	// Source - used for https://github.com/moby/moby/blob/v24.0.6/api/types/mount/mount.go#L30
	Source string `json:"source,omitempty"`

	// Target - used for https://github.com/moby/moby/blob/v24.0.6/api/types/mount/mount.go#L31
	Target string `json:"target,omitempty"`

	// ReadOnly - used for https://github.com/moby/moby/blob/v24.0.6/api/types/mount/mount.go#L32
	ReadOnly bool `json:"read_only,omitempty"`

	// Consistency - used for https://github.com/moby/moby/blob/v24.0.6/api/types/mount/mount.go#L33
	Consistency mount.Consistency `json:"consistency,omitempty"`

	// BindOptions - used for https://github.com/moby/moby/blob/v24.0.6/api/types/mount/mount.go#L35
	BindOptions *BindOptions `json:"bind_options,omitempty"`

	// VolumeOptions - used for https://github.com/moby/moby/blob/v24.0.6/api/types/mount/mount.go#L36
	VolumeOptions *VolumeOptions `json:"volume_options,omitempty"`

	// TmpfsOptions - used for https://github.com/moby/moby/blob/v24.0.6/api/types/mount/mount.go#L37
	TmpfsOptions *TmpfsOptions `json:"tmpfs_options,omitempty"`

	// OnMount - an optional function to be called before the mount is being created.
	// this can be useful for lazy evaluation such as creating directories or resources only if needed.
	// available only via code, not available in config files
	OnMount func() `json:"-"`
}

// BindOptions allow specifying Docker bind params for a Docker Mount.
type BindOptions struct {
	// Propagation - used for https://github.com/moby/moby/blob/v24.0.6/api/types/mount/mount.go#L85
	Propagation mount.Propagation `json:"propagation,omitempty"`

	// NonRecursive - used for https://github.com/moby/moby/blob/v24.0.6/api/types/mount/mount.go#L86
	NonRecursive bool `json:"non_recursive,omitempty"`

	// CreateMountpoint - used for https://github.com/moby/moby/blob/v24.0.6/api/types/mount/mount.go#L87
	CreateMountpoint bool `json:"create_mountpoint,omitempty"`
}

// VolumeOptions allow specifying Docker volume params for a Docker Mount.
type VolumeOptions struct {
	// NoCopy - used for https://github.com/moby/moby/blob/v24.0.6/api/types/mount/mount.go#L92
	NoCopy bool `json:"no_copy,omitempty"`

	// Labels - used for https://github.com/moby/moby/blob/v24.0.6/api/types/mount/mount.go#L93
	Labels map[string]string `json:"labels,omitempty"`

	// DriverConfig - used for https://github.com/moby/moby/blob/v24.0.6/api/types/mount/mount.go#L94
	DriverConfig *Driver `json:"driver_config,omitempty"`
}

// Driver allow specifying Docker Driver.
type Driver struct {
	// Name - used for https://github.com/moby/moby/blob/v24.0.6/api/types/mount/mount.go#L99
	Name string `json:"name,omitempty"`

	// Options - used for https://github.com/moby/moby/blob/v24.0.6/api/types/mount/mount.go#L100
	Options map[string]string `json:"options,omitempty"`
}

// TmpfsOptions allow specifying Docker tmpfs config.
type TmpfsOptions struct {
	// SizeBytes - used for https://github.com/moby/moby/blob/v24.0.6/api/types/mount/mount.go#L113
	SizeBytes int64 `json:"size_bytes,omitempty"`

	// Mode - used for https://github.com/moby/moby/blob/v24.0.6/api/types/mount/mount.go#L115
	Mode os.FileMode `json:"mode,omitempty"`
}

// PlatformConfig allow specifying Docker platform config.
type PlatformConfig struct {
	// Architecture - used for https://github.com/opencontainers/image-spec/blob/v1.1.0-rc4/specs-go/v1/descriptor.go#L56
	Architecture string `json:"architecture,omitempty"`

	// OS - used for https://github.com/opencontainers/image-spec/blob/v1.1.0-rc4/specs-go/v1/descriptor.go#L56
	OS string `json:"os,omitempty"`

	// OSVersion - used for https://github.com/opencontainers/image-spec/blob/v1.1.0-rc4/specs-go/v1/descriptor.go#L56
	OSVersion string `json:"os_version,omitempty"`

	// OSFeatures - used for https://github.com/opencontainers/image-spec/blob/v1.1.0-rc4/specs-go/v1/descriptor.go#L56
	OSFeatures []string `json:"os_features,omitempty"`

	// Variant - used for https://github.com/opencontainers/image-spec/blob/v1.1.0-rc4/specs-go/v1/descriptor.go#L56
	Variant string `json:"variant,omitempty"`
}

// StrSlice is a wrapper for strslice.StrSlice that works with yaml in addition to json.
type StrSlice strslice.StrSlice

func (s *StrSlice) UnmarshalYAML(value *yaml.Node) error {
	var p []string
	err := value.Decode(&p)
	if err != nil {
		var str string
		err = value.Decode(&str)
		if err != nil {
			return err
		}

		p = append(p, str)
	}

	*s = p
	return nil
}

// runConfig holds the configuration for running a Docker container.
type runConfig struct {
	hostname         string
	containerConfig  *container.Config
	hostConfig       *container.HostConfig
	networkingConfig *network.NetworkingConfig
	platformConfig   *ocispec.Platform
	waiters          []waiterFunc
}

// initialize validates and initializes the runConfig based on the provided Config and network information.
func (c Config) initialize(network *Network, imageCloneTag string) (*runConfig, error) {
	if c.Name == "" {
		return nil, ErrInvalidConfig{Property: "name", Msg: "cannot be empty"}
	}

	if c.Image == "" {
		return nil, ErrInvalidConfig{Property: "image", Msg: "cannot be empty"}
	}

	if l := len(c.ConsoleSize); l != 0 && l != 2 {
		return nil, ErrInvalidConfig{Property: "console_size", Msg: "must have exactly two elements"}
	}

	waiters := make([]waiterFunc, len(c.Waiters))
	for i, waiter := range c.Waiters {
		f, err := validateWaiter(waiter)
		if err != nil {
			return nil, err
		}

		waiters[i] = f
	}

	result := &runConfig{
		containerConfig: c.containerConfig(imageCloneTag),
		hostConfig:      c.hostConfig(network),
		platformConfig:  c.PlatformConfig.build(),
		waiters:         waiters,
	}

	return result, nil
}

func (c Config) imagePullOptions() (client.ImagePullOptions, error) {
	result := client.ImagePullOptions{}

	if c.ImagePullOptions != nil {
		var auth string
		if c.ImagePullOptions.RegistryAuthFunc != nil {
			var err error
			auth, err = c.ImagePullOptions.RegistryAuthFunc()
			if err != nil {
				return client.ImagePullOptions{}, fmt.Errorf("failed to get registry auth: %w", err)
			}
		} else {
			auth = c.ImagePullOptions.RegistryAuth
		}

		result.All = c.ImagePullOptions.All
		result.RegistryAuth = auth
		// Note: PrivilegeFunc signature changed in v29 - now takes context.Context
		if c.ImagePullOptions.PrivilegeFunc != nil {
			result.PrivilegeFunc = func(_ context.Context) (string, error) {
				return c.ImagePullOptions.PrivilegeFunc()
			}
		}
		// Platform is now an array of platforms in v29
		if c.ImagePullOptions.Platform != "" {
			result.Platforms = []ocispec.Platform{{OS: c.ImagePullOptions.Platform}}
		}
	}

	return result, nil
}

func (c Config) containerConfig(imageCloneTag string) *container.Config {
	env := make([]string, 0, len(c.Env))
	for key, value := range c.Env {
		env = append(env, fmt.Sprintf("%s=%s", key, value))
	}

	return &container.Config{
		Hostname:        c.Hostname,
		Domainname:      c.Domainname,
		User:            c.User,
		AttachStdin:     c.AttachStdin,
		AttachStdout:    c.AttachStdout,
		AttachStderr:    c.AttachStderr,
		ExposedPorts:    nil,
		Tty:             c.Tty,
		OpenStdin:       c.OpenStdin,
		StdinOnce:       c.StdinOnce,
		Env:             env,
		Cmd:             strslice.StrSlice(c.Cmd),
		Healthcheck:     c.Healthcheck.build(),
		ArgsEscaped:     c.ArgsEscaped,
		Image:           imageCloneTag,
		Volumes:         c.Volumes,
		WorkingDir:      c.WorkingDir,
		Entrypoint:      strslice.StrSlice(c.Entrypoint),
		NetworkDisabled: c.NetworkDisabled,
		// MacAddress has been removed in v29 - now set via network endpoint settings
		OnBuild:     c.OnBuild,
		Labels:      c.Labels,
		StopSignal:  c.StopSignal,
		StopTimeout: c.StopTimeout,
		Shell:       strslice.StrSlice(c.Shell),
	}
}

func (c *Healthcheck) build() *container.HealthConfig {
	if c == nil {
		return nil
	}

	return &container.HealthConfig{
		Test:        c.Test,
		Interval:    c.Interval,
		Timeout:     c.Timeout,
		StartPeriod: c.StartPeriod,
		Retries:     c.Retries,
	}
}

func (c Config) hostConfig(network *Network) *container.HostConfig {
	var consoleSize [2]uint
	if len(c.ConsoleSize) > 0 {
		consoleSize = [2]uint{c.ConsoleSize[0], c.ConsoleSize[1]}
	}
	return &container.HostConfig{
		Binds:           c.Binds,
		ContainerIDFile: c.ContainerIDFile,
		LogConfig:       c.LogConfig.build(),
		RestartPolicy:   c.RestartPolicy.build(),
		AutoRemove:      !network.KeepStoppedContainers,
		VolumeDriver:    c.VolumeDriver,
		VolumesFrom:     c.VolumesFrom,
		ConsoleSize:     consoleSize,
		Annotations:     c.Annotations,
		CapAdd:          strslice.StrSlice(c.CapAdd),
		CapDrop:         strslice.StrSlice(c.CapDrop),
		CgroupnsMode:    c.CgroupnsMode,
		DNS:             convertDNSToNetipAddrs(c.DNS),
		DNSOptions:      c.DNSOptions,
		DNSSearch:       c.DNSSearch,
		ExtraHosts:      c.ExtraHosts,
		GroupAdd:        c.GroupAdd,
		IpcMode:         c.IpcMode,
		Cgroup:          c.Cgroup,
		Links:           c.Links,
		OomScoreAdj:     c.OomScoreAdj,
		PidMode:         c.PidMode,
		Privileged:      c.Privileged,
		PublishAllPorts: c.PublishAllPorts,
		ReadonlyRootfs:  c.ReadonlyRootfs,
		SecurityOpt:     c.SecurityOpt,
		StorageOpt:      c.StorageOpt,
		Tmpfs:           c.Tmpfs,
		UTSMode:         c.UTSMode,
		UsernsMode:      c.UsernsMode,
		ShmSize:         c.ShmSize,
		Sysctls:         c.Sysctls,
		Runtime:         c.Runtime,
		Isolation:       c.Isolation,
		Resources:       c.Resources.build(),
		Mounts:          mapSlice(c.Mounts, Mount.build),
		MaskedPaths:     c.MaskedPaths,
		ReadonlyPaths:   c.ReadonlyPaths,
		Init:            c.Init,
	}
}

func (c *LogConfig) build() container.LogConfig {
	if c == nil {
		return container.LogConfig{}
	}

	return container.LogConfig{
		Type:   c.Type,
		Config: c.Config,
	}
}

func (c *RestartPolicy) build() container.RestartPolicy {
	if c == nil {
		return container.RestartPolicy{}
	}

	return container.RestartPolicy{
		Name:              container.RestartPolicyMode(c.Name),
		MaximumRetryCount: c.MaximumRetryCount,
	}
}

func (c *Resources) build() container.Resources {
	if c == nil {
		return container.Resources{}
	}

	return container.Resources{
		CPUShares:            c.CPUShares,
		Memory:               c.Memory,
		NanoCPUs:             c.NanoCPUs,
		CgroupParent:         c.CgroupParent,
		BlkioWeight:          c.BlkioWeight,
		BlkioWeightDevice:    mapSlice(c.BlkioWeightDevice, WeightDevice.build),
		BlkioDeviceReadBps:   mapSlice(c.BlkioDeviceReadBps, ThrottleDevice.build),
		BlkioDeviceWriteBps:  mapSlice(c.BlkioDeviceWriteBps, ThrottleDevice.build),
		BlkioDeviceReadIOps:  mapSlice(c.BlkioDeviceReadIOps, ThrottleDevice.build),
		BlkioDeviceWriteIOps: mapSlice(c.BlkioDeviceWriteIOps, ThrottleDevice.build),
		CPUPeriod:            c.CPUPeriod,
		CPUQuota:             c.CPUQuota,
		CPURealtimePeriod:    c.CPURealtimePeriod,
		CPURealtimeRuntime:   c.CPURealtimeRuntime,
		CpusetCpus:           c.CpusetCpus,
		CpusetMems:           c.CpusetMems,
		Devices:              mapSlice(c.Devices, DeviceMapping.build),
		DeviceCgroupRules:    c.DeviceCgroupRules,
		DeviceRequests:       mapSlice(c.DeviceRequests, DeviceRequest.build),
		// KernelMemoryTCP removed in v29
		MemoryReservation: c.MemoryReservation,
		MemorySwap:        c.MemorySwap,
		MemorySwappiness:  c.MemorySwappiness,
		OomKillDisable:    c.OomKillDisable,
		PidsLimit:         c.PidsLimit,
		Ulimits:           mapSlice(c.Ulimits, Ulimit.build),
		CPUCount:          c.CPUCount,
		CPUPercent:        c.CPUPercent,
		IOMaximumIOps:     c.IOMaximumIOps,
		IOMaximumBandwidth: c.IOMaximumBandwidth,
	}
}

func (c WeightDevice) build() *blkiodev.WeightDevice {
	return &blkiodev.WeightDevice{
		Path:   c.Path,
		Weight: c.Weight,
	}
}

func (c ThrottleDevice) build() *blkiodev.ThrottleDevice {
	return &blkiodev.ThrottleDevice{
		Path: c.Path,
		Rate: c.Rate,
	}
}

func (c DeviceMapping) build() container.DeviceMapping {
	return container.DeviceMapping{
		PathOnHost:        c.PathOnHost,
		PathInContainer:   c.PathInContainer,
		CgroupPermissions: c.CgroupPermissions,
	}
}

func (c DeviceRequest) build() container.DeviceRequest {
	return container.DeviceRequest{
		Driver:       c.Driver,
		Count:        c.Count,
		DeviceIDs:    c.DeviceIDs,
		Capabilities: c.Capabilities,
		Options:      c.Options,
	}
}

func (c Ulimit) build() *units.Ulimit {
	return &units.Ulimit{
		Name: c.Name,
		Hard: c.Hard,
		Soft: c.Soft,
	}
}

func (c Mount) build() mount.Mount {
	return mount.Mount{
		Type:          c.Type,
		Source:        c.Source,
		Target:        c.Target,
		ReadOnly:      c.ReadOnly,
		Consistency:   c.Consistency,
		BindOptions:   c.BindOptions.build(),
		VolumeOptions: c.VolumeOptions.build(),
		TmpfsOptions:  c.TmpfsOptions.build(),
	}
}

func (c *BindOptions) build() *mount.BindOptions {
	if c == nil {
		return nil
	}

	return &mount.BindOptions{
		Propagation:      c.Propagation,
		NonRecursive:     c.NonRecursive,
		CreateMountpoint: c.CreateMountpoint,
	}
}

func (c *VolumeOptions) build() *mount.VolumeOptions {
	if c == nil {
		return nil
	}

	return &mount.VolumeOptions{
		NoCopy:       c.NoCopy,
		Labels:       c.Labels,
		DriverConfig: c.DriverConfig.build(),
	}
}

func (c *Driver) build() *mount.Driver {
	if c == nil {
		return nil
	}

	return &mount.Driver{
		Name:    c.Name,
		Options: c.Options,
	}
}

func (c *TmpfsOptions) build() *mount.TmpfsOptions {
	if c == nil {
		return nil
	}

	return &mount.TmpfsOptions{
		SizeBytes: c.SizeBytes,
		Mode:      c.Mode,
	}
}

func (c *PlatformConfig) build() *ocispec.Platform {
	if c == nil {
		return nil
	}

	return &ocispec.Platform{
		Architecture: c.Architecture,
		OS:           c.OS,
		OSVersion:    c.OSVersion,
		OSFeatures:   c.OSFeatures,
		Variant:      c.Variant,
	}
}

func mapSlice[T1, T2 any](slice []T1, mapper func(T1) T2) []T2 {
	result := make([]T2, len(slice))
	for i, m := range slice {
		result[i] = mapper(m)
	}

	return result
}

// ErrInvalidConfig represents an error in case an invalid config is given.
type ErrInvalidConfig struct {
	Property string
	Msg      string
}

func (e ErrInvalidConfig) Error() string {
	return fmt.Sprintf("invalid docker config - property %s: %s", e.Property, e.Msg)
}

// convertDNSToNetipAddrs converts DNS server strings to netip.Addr slice
func convertDNSToNetipAddrs(dns []string) []netip.Addr {
	if len(dns) == 0 {
		return nil
	}
	result := make([]netip.Addr, 0, len(dns))
	for _, d := range dns {
		addr, err := netip.ParseAddr(d)
		if err == nil {
			result = append(result, addr)
		}
	}
	return result
}
