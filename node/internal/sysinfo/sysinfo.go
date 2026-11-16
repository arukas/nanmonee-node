// Package sysinfo collects the host facts and live resource usage a node
// reports to the panel.
//
// Everything is read from procfs/sysfs and statfs; the package never shells out,
// never links cgo, and never sends a value it could not read. Missing sources
// degrade to zero values so one absent file cannot stop the report.
package sysinfo

import (
	"os"
	"path"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

// ReportProtocol names this document so the panel can reject an agent that
// sends anything else instead of storing a half-understood snapshot.
const ReportProtocol = "nanmonee-sysinfo-v1"

// procRoot, sysRoot and osRelease are variables so tests can point the collector
// at a fixture tree instead of the live host.
var (
	procRoot     = "/proc"
	sysRoot      = "/sys"
	osRelease    = "/etc/os-release"
	dockerMarker = "/.dockerenv"
)

// Snapshot is one complete sample. It is the wire shape reported to the panel,
// so every field carries an explicit, stable JSON name.
type Snapshot struct {
	Protocol      string `json:"protocol"`
	AgentVersion  string `json:"agent_version"`
	KernelVersion string `json:"kernel_version"`
	KernelCommit  string `json:"kernel_commit"`
	SampledAt     int64  `json:"sampled_at"`
	UptimeSeconds int64  `json:"uptime_seconds"`
	System        System `json:"system"`
	Usage         Usage  `json:"usage"`
}

// System is the static configuration of the host: it changes only when the
// machine or its kernel does, not on every sample.
type System struct {
	Hostname       string `json:"hostname"`
	OS             string `json:"os"`
	Kernel         string `json:"kernel"`
	Arch           string `json:"arch"`
	Virtualization string `json:"virtualization"`
	BootTime       int64  `json:"boot_time"`
	CPU            CPU    `json:"cpu"`
	MemoryTotal    int64  `json:"memory_total_bytes"`
	SwapTotal      int64  `json:"swap_total_bytes"`
}

// CPU describes the processor set. Cores is the logical count from procfs.
type CPU struct {
	Model         string `json:"model"`
	Cores         int    `json:"cores"`
	PhysicalCores int    `json:"physical_cores"`
	MHz           int    `json:"mhz"`
}

// Usage is the live resource sample.
type Usage struct {
	CPUPercent float64 `json:"cpu_percent"`
	Load       Load    `json:"load"`
	Memory     Memory  `json:"memory"`
	Swap       Memory  `json:"swap"`
	Disk       []Disk  `json:"disk"`
	Process    Process `json:"process"`
	// DiskError explains why the filesystem list is empty, so the panel can tell
	// "no real filesystem" apart from "the reading failed".
	DiskError string `json:"disk_error"`
}

// Load is the one, five and fifteen minute run queue average.
type Load struct {
	One     float64 `json:"one"`
	Five    float64 `json:"five"`
	Fifteen float64 `json:"fifteen"`
}

// Memory is one memory pool. Used never exceeds Total.
type Memory struct {
	Total     int64 `json:"total_bytes"`
	Used      int64 `json:"used_bytes"`
	Available int64 `json:"available_bytes"`
}

// Disk is one real filesystem, identified by its mount point.
type Disk struct {
	Mount     string `json:"mount"`
	Total     int64  `json:"total_bytes"`
	Used      int64  `json:"used_bytes"`
	Available int64  `json:"available_bytes"`
}

// Process reports the agent's own footprint, so an operator can spot one
// instance misbehaving without shelling into the host.
type Process struct {
	RSSBytes   int64 `json:"rss_bytes"`
	Threads    int   `json:"threads"`
	Goroutines int   `json:"goroutines"`
}

// maxDisks bounds the filesystem list carried in one report.
const maxDisks = 8

// pseudoFilesystems are skipped: they report host or kernel state rather than
// storage, and would make a usage reading meaningless.
var pseudoFilesystems = map[string]bool{
	"proc": true, "sysfs": true, "devtmpfs": true, "devpts": true, "tmpfs": true,
	"cgroup": true, "cgroup2": true, "pstore": true, "securityfs": true, "debugfs": true,
	"tracefs": true, "configfs": true, "fusectl": true, "mqueue": true, "hugetlbfs": true,
	"bpf": true, "autofs": true, "binfmt_misc": true, "nsfs": true, "rpc_pipefs": true,
	"ramfs": true,
}

// Collector keeps the previous CPU counters so each sample is a rate over the
// interval since the last call rather than an average since boot. It is safe for
// concurrent use, though the worker serializes its own calls.
type Collector struct {
	AgentVersion  string
	KernelVersion string
	KernelCommit  string

	mu   sync.Mutex
	last cpuTimes
}

// New returns a collector that stamps every sample with the given build
// identity.
func New(agentVersion, kernelVersion, kernelCommit string) *Collector {
	return &Collector{AgentVersion: agentVersion, KernelVersion: kernelVersion, KernelCommit: kernelCommit}
}

// Sample reads the host and returns one report. Errors are per-field: a value
// that cannot be read stays zero instead of failing the whole report, because a
// partially readable host still gives the panel useful information.
func (c *Collector) Sample() Snapshot {
	now := time.Now()
	snapshot := Snapshot{
		Protocol:      ReportProtocol,
		AgentVersion:  c.AgentVersion,
		KernelVersion: c.KernelVersion,
		KernelCommit:  c.KernelCommit,
		SampledAt:     now.Unix(),
	}

	uptime := 0.0
	if content, err := os.ReadFile(path.Join(procRoot, "uptime")); err == nil {
		uptime, _ = parseUptime(string(content))
	}
	snapshot.UptimeSeconds = int64(uptime)
	snapshot.System.BootTime = now.Unix() - int64(uptime)

	snapshot.System.Hostname, _ = os.Hostname()
	snapshot.System.OS = readOSRelease(osRelease)
	if content, err := os.ReadFile(path.Join(procRoot, "sys/kernel/osrelease")); err == nil {
		snapshot.System.Kernel = strings.TrimSpace(string(content))
	}
	snapshot.System.Arch = archName(runtime.GOARCH)

	var cpuinfo string
	if content, err := os.ReadFile(path.Join(procRoot, "cpuinfo")); err == nil {
		cpuinfo = string(content)
		info := parseCPUInfo(cpuinfo)
		snapshot.System.CPU = CPU{Model: info.model, Cores: info.logical, PhysicalCores: info.physical, MHz: info.mhz}
	}
	snapshot.System.Virtualization = readVirtualization(cpuinfo)
	if snapshot.System.CPU.Cores == 0 {
		snapshot.System.CPU.Cores = runtime.NumCPU()
	}
	if snapshot.System.CPU.PhysicalCores == 0 {
		snapshot.System.CPU.PhysicalCores = snapshot.System.CPU.Cores
	}

	if content, err := os.ReadFile(path.Join(procRoot, "meminfo")); err == nil {
		memory := parseMeminfo(string(content))
		snapshot.System.MemoryTotal = memory.total
		snapshot.System.SwapTotal = memory.swapTotal
		snapshot.Usage.Memory = memory.used
		snapshot.Usage.Swap = memory.swapUsed
	}

	if content, err := os.ReadFile(path.Join(procRoot, "loadavg")); err == nil {
		snapshot.Usage.Load = parseLoadavg(string(content))
	}

	snapshot.Usage.CPUPercent = c.cpuPercent()
	snapshot.Usage.Disk, snapshot.Usage.DiskError = c.disks()
	snapshot.Usage.Process = readProcess()

	return snapshot
}

// cpuPercent turns the two total counters into a percentage. The first call
// falls back to the average since boot, which is still a truthful reading.
func (c *Collector) cpuPercent() float64 {
	content, err := os.ReadFile(path.Join(procRoot, "stat"))
	if err != nil {
		return 0
	}
	current, ok := parseStat(string(content))
	if !ok {
		return 0
	}

	c.mu.Lock()
	previous := c.last
	c.last = current
	c.mu.Unlock()

	if previous.total == 0 || current.total <= previous.total {
		return clampPercent(current.percent())
	}

	idle := current.idle - previous.idle
	total := current.total - previous.total
	if total <= 0 {
		return 0
	}

	return clampPercent(float64(total-idle) * 100 / float64(total))
}

func clampPercent(value float64) float64 {
	if value < 0 {
		return 0
	}
	if value > 100 {
		return 100
	}
	// Keep one decimal; the panel stores two.
	return float64(int(value*10+0.5)) / 10
}

// disks reports the real mounted filesystems, largest first. A host without a
// readable mount table returns an explanation rather than a silent empty list.
func (c *Collector) disks() ([]Disk, string) {
	content, err := os.ReadFile(path.Join(procRoot, "mounts"))
	if err != nil {
		return nil, "the mount table is unreadable"
	}
	mounts := parseMounts(string(content))
	if len(mounts) == 0 {
		return nil, "no real filesystem is mounted"
	}

	disks := make([]Disk, 0, len(mounts))
	for _, mount := range mounts {
		var stat syscall.Statfs_t
		if err := syscall.Statfs(mount, &stat); err != nil {
			continue
		}
		blockSize := int64(stat.Bsize)
		if blockSize <= 0 {
			continue
		}
		total := int64(stat.Blocks) * blockSize
		available := int64(stat.Bavail) * blockSize
		if total <= 0 {
			continue
		}
		used := total - available
		if used < 0 {
			used = 0
		}
		disks = append(disks, Disk{Mount: mount, Total: total, Used: used, Available: available})
	}
	if len(disks) == 0 {
		return nil, "no mounted filesystem could be measured"
	}

	sort.Slice(disks, func(i, j int) bool {
		if disks[i].Total != disks[j].Total {
			return disks[i].Total > disks[j].Total
		}
		return disks[i].Mount < disks[j].Mount
	})
	if len(disks) > maxDisks {
		disks = disks[:maxDisks]
	}

	return disks, ""
}

// readProcess reports this process only; /proc/self is always available on
// Linux.
func readProcess() Process {
	process := Process{Goroutines: runtime.NumGoroutine()}
	if content, err := os.ReadFile(path.Join(procRoot, "self/statm")); err == nil {
		fields := strings.Fields(string(content))
		if len(fields) >= 2 {
			if pages, err := strconv.ParseInt(fields[1], 10, 64); err == nil {
				process.RSSBytes = pages * int64(os.Getpagesize())
			}
		}
	}
	if content, err := os.ReadFile(path.Join(procRoot, "self/status")); err == nil {
		process.Threads = parseThreads(string(content))
	}
	return process
}

// readOSRelease returns PRETTY_NAME when present, else NAME plus VERSION.
func readOSRelease(file string) string {
	content, err := os.ReadFile(file)
	if err != nil {
		return ""
	}
	values := map[string]string{}
	for _, line := range strings.Split(string(content), "\n") {
		key, value, ok := strings.Cut(strings.TrimSpace(line), "=")
		if !ok {
			continue
		}
		values[key] = strings.Trim(value, `"`)
	}
	if pretty := values["PRETTY_NAME"]; pretty != "" {
		return pretty
	}
	return strings.TrimSpace(values["NAME"] + " " + values["VERSION"])
}

// readVirtualization reports the hypervisor when the CPU advertises one and the
// DMI vendor or a container marker is readable. "none" means the CPU flags say
// bare metal, "" means it could not be determined.
func readVirtualization(cpuinfo string) string {
	if cpuinfo == "" {
		return ""
	}
	if !hasFlag(cpuinfo, "hypervisor") {
		return "none"
	}
	if _, err := os.Stat(dockerMarker); err == nil {
		return "container"
	}
	if content, err := os.ReadFile(path.Join(sysRoot, "class/dmi/id/product_name")); err == nil {
		name := strings.ToLower(strings.TrimSpace(string(content)))
		for _, known := range []struct{ needle, label string }{
			{"kvm", "kvm"}, {"vmware", "vmware"}, {"virtualbox", "virtualbox"},
			{"amazon ec2", "amazon"}, {"google compute", "gce"}, {"microsoft", "hyper-v"},
			{"openstack", "openstack"}, {"bochs", "qemu"}, {"qemu", "qemu"},
		} {
			if strings.Contains(name, known.needle) {
				return known.label
			}
		}
	}
	return "hypervisor"
}

func hasFlag(cpuinfo, flag string) bool {
	for _, line := range strings.Split(cpuinfo, "\n") {
		key, value, ok := strings.Cut(line, ":")
		if !ok || strings.TrimSpace(key) != "flags" {
			continue
		}
		for _, candidate := range strings.Fields(value) {
			if candidate == flag {
				return true
			}
		}
	}
	return false
}

// archName maps Go's architecture names to the uname spelling operators expect.
func archName(arch string) string {
	switch arch {
	case "amd64":
		return "x86_64"
	case "arm64":
		return "aarch64"
	case "386":
		return "i686"
	default:
		return arch
	}
}
