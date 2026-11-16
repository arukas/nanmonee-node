package sysinfo

import (
	"strconv"
	"strings"
)

// cpuTimes is one /proc/stat "cpu" aggregate line reduced to the two counters a
// rate needs: everything the CPU spent time on, and the idle part of it.
type cpuTimes struct {
	total uint64
	idle  uint64
}

// percent is the average busy share since boot, used for the first sample
// where there is no previous counter to subtract.
func (c cpuTimes) percent() float64 {
	if c.total == 0 {
		return 0
	}
	return float64(c.total-c.idle) * 100 / float64(c.total)
}

// parseStat reads the aggregate "cpu" line. /proc/stat starts with per-CPU lines
// followed by the aggregate; only the aggregate is used here.
func parseStat(content string) (cpuTimes, bool) {
	for _, line := range strings.Split(content, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 5 || fields[0] != "cpu" {
			continue
		}
		var values []uint64
		for _, field := range fields[1:] {
			// The kernel has occasionally appended columns; anything that is not
			// a number ends the line's usable part.
			value, err := strconv.ParseUint(field, 10, 64)
			if err != nil {
				break
			}
			values = append(values, value)
		}
		if len(values) < 4 {
			return cpuTimes{}, false
		}
		var total uint64
		for _, value := range values {
			total += value
		}
		// user nice system idle iowait irq softirq steal guest guest_nice.
		// guest and guest_nice are already counted in user and nice, so the
		// first eight columns are the real total.
		if len(values) > 8 {
			total = 0
			for _, value := range values[:8] {
				total += value
			}
		}
		idle := values[3]
		if len(values) > 4 {
			idle += values[4]
		}
		if total == 0 {
			return cpuTimes{}, false
		}
		return cpuTimes{total: total, idle: idle}, true
	}
	return cpuTimes{}, false
}

func parseUptime(content string) (float64, bool) {
	fields := strings.Fields(content)
	if len(fields) == 0 {
		return 0, false
	}
	value, err := strconv.ParseFloat(fields[0], 64)
	if err != nil || value < 0 {
		return 0, false
	}
	return value, true
}

func parseLoadavg(content string) Load {
	fields := strings.Fields(content)
	values := make([]float64, 0, 3)
	for _, field := range fields {
		if len(values) == 3 {
			break
		}
		value, err := strconv.ParseFloat(field, 64)
		if err != nil {
			break
		}
		values = append(values, value)
	}
	load := Load{}
	if len(values) > 0 {
		load.One = values[0]
	}
	if len(values) > 1 {
		load.Five = values[1]
	}
	if len(values) > 2 {
		load.Fifteen = values[2]
	}
	return load
}

type cpuInfo struct {
	model    string
	logical  int
	physical int
	mhz      int
}

// parseCPUInfo counts processors and distinct core pairs, which is the logical
// and physical core count consumers expect. A container sees the host's CPUs,
// so these numbers describe the machine, not the cgroup quota.
func parseCPUInfo(content string) cpuInfo {
	info := cpuInfo{}
	physical := map[string]bool{}
	var currentPhysical, currentCore string
	for _, block := range strings.Split(content, "\n\n") {
		if strings.TrimSpace(block) == "" {
			continue
		}
		info.logical++
		currentPhysical, currentCore = "", ""
		for _, line := range strings.Split(block, "\n") {
			key, value, ok := strings.Cut(line, ":")
			if !ok {
				continue
			}
			value = strings.TrimSpace(value)
			switch strings.TrimSpace(key) {
			case "model name":
				if info.model == "" {
					info.model = value
				}
			case "cpu MHz":
				if info.mhz == 0 {
					if mhz, err := strconv.ParseFloat(value, 64); err == nil && mhz > 0 {
						info.mhz = int(mhz + 0.5)
					}
				}
			case "physical id":
				currentPhysical = value
			case "core id":
				currentCore = value
			}
		}
		if currentCore != "" {
			physical[currentPhysical+"/"+currentCore] = true
		}
	}
	info.physical = len(physical)
	return info
}

type memoryInfo struct {
	total     int64
	used      Memory
	swapTotal int64
	swapUsed  Memory
}

// parseMeminfo maps /proc/meminfo onto the used/total pair the panel displays.
// Used is Total minus what the kernel reports as available, which is the only
// figure that accounts for reclaimable page cache.
func parseMeminfo(content string) memoryInfo {
	values := map[string]int64{}
	for _, line := range strings.Split(content, "\n") {
		key, value, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		fields := strings.Fields(value)
		if len(fields) == 0 {
			continue
		}
		amount, err := strconv.ParseInt(fields[0], 10, 64)
		if err != nil || amount < 0 {
			continue
		}
		// meminfo values are in kB unless the line says otherwise; the only
		// alternative the kernel emits is "kB".
		if len(fields) > 1 && fields[1] != "kB" {
			continue
		}
		values[strings.TrimSpace(key)] = amount * 1024
	}

	info := memoryInfo{total: values["MemTotal"]}
	available := values["MemAvailable"]
	if available <= 0 && info.total > 0 {
		// Older kernels have no MemAvailable; approximate it the way the kernel
		// documentation describes: free + reclaimable.
		available = values["MemFree"] + values["Buffers"] + values["Cached"]
	}
	if available > info.total {
		available = info.total
	}
	info.used = usedPool(info.total, available)

	info.swapTotal = values["SwapTotal"]
	swapFree := values["SwapFree"]
	if swapFree > info.swapTotal {
		swapFree = info.swapTotal
	}
	info.swapUsed = usedPool(info.swapTotal, swapFree)

	return info
}

func usedPool(total, available int64) Memory {
	if total <= 0 {
		return Memory{}
	}
	if available < 0 {
		available = 0
	}
	used := total - available
	if used < 0 {
		used = 0
	}
	return Memory{Total: total, Used: used, Available: available}
}

// parseMounts returns the real filesystem mount points, skipping pseudo
// filesystems, duplicates and paths the agent cannot stat.
func parseMounts(content string) []string {
	seen := map[string]bool{}
	mounts := make([]string, 0, 8)
	for _, line := range strings.Split(content, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 3 {
			continue
		}
		filesystem := fields[2]
		// Overlay and squashfs report the immutable image, not the storage the
		// operator can grow; they are not actionable.
		if pseudoFilesystems[filesystem] || filesystem == "overlay" || filesystem == "aufs" {
			continue
		}
		mountPoint := unescapeMount(fields[1])
		if mountPoint == "" || seen[mountPoint] {
			continue
		}
		seen[mountPoint] = true
		mounts = append(mounts, mountPoint)
	}
	return mounts
}

// unescapeMount reverses the octal escapes the kernel uses for spaces and tabs
// in /proc/mounts (\040 and \011).
func unescapeMount(value string) string {
	if !strings.Contains(value, `\0`) {
		return value
	}
	var builder strings.Builder
	for index := 0; index < len(value); index++ {
		if value[index] == '\\' && index+3 < len(value) && value[index+1] >= '0' && value[index+1] <= '7' {
			code := 0
			for offset := 1; offset <= 3; offset++ {
				code = code*8 + int(value[index+offset]-'0')
			}
			builder.WriteByte(byte(code))
			index += 3
			continue
		}
		builder.WriteByte(value[index])
	}
	return builder.String()
}

func parseThreads(content string) int {
	for _, line := range strings.Split(content, "\n") {
		key, value, ok := strings.Cut(line, ":")
		if !ok || strings.TrimSpace(key) != "Threads" {
			continue
		}
		threads, err := strconv.Atoi(strings.TrimSpace(value))
		if err != nil || threads < 0 {
			return 0
		}
		return threads
	}
	return 0
}
