package sysinfo

import (
	"os"
	"path/filepath"
	"testing"
)

// writeFile creates one fixture file under root, making parents as needed.
func writeFile(t *testing.T, root, name, content string) {
	t.Helper()
	target := filepath.Join(root, name)
	if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
		t.Fatalf("create fixture dir: %v", err)
	}
	if err := os.WriteFile(target, []byte(content), 0o644); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
}

// useFixtures points the collector at a temporary proc/sys tree and restores the
// real roots when the test ends.
func useFixtures(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	previousProc, previousSys := procRoot, sysRoot
	previousRelease, previousMarker := osRelease, dockerMarker
	t.Cleanup(func() {
		procRoot, sysRoot = previousProc, previousSys
		osRelease, dockerMarker = previousRelease, previousMarker
	})
	procRoot = filepath.Join(root, "proc")
	sysRoot = filepath.Join(root, "sys")
	osRelease = filepath.Join(root, "etc/os-release")
	dockerMarker = filepath.Join(root, "dockerenv")
	return root
}

const statFixtureV1 = `cpu  100 0 100 800 0 0 0 0 0 0
cpu0 50 0 50 400 0 0 0 0 0 0
cpu1 50 0 50 400 0 0 0 0 0 0
intr 1 2 3
`

const statFixtureV2 = `cpu  200 0 200 1400 0 0 0 0 0 0
cpu0 100 0 100 700 0 0 0 0 0 0
cpu1 100 0 100 700 0 0 0 0 0 0
intr 1 2 3
`

const meminfoFixture = `MemTotal:        8000000 kB
MemFree:         1000000 kB
MemAvailable:    2000000 kB
Buffers:          100000 kB
Cached:          1000000 kB
SwapTotal:       2000000 kB
SwapFree:        1500000 kB
`

const cpuinfoFixture = `processor	: 0
vendor_id	: GenuineIntel
model name	: Intel(R) Xeon(R) CPU E5-2680 v4 @ 2.40GHz
cpu MHz		: 2400.000
physical id	: 0
core id		: 0
flags		: fpu vme de pse tsc msr pae mce hypervisor

processor	: 1
vendor_id	: GenuineIntel
model name	: Intel(R) Xeon(R) CPU E5-2680 v4 @ 2.40GHz
cpu MHz		: 2400.000
physical id	: 0
core id		: 0
flags		: fpu vme de pse tsc msr pae mce hypervisor

processor	: 2
vendor_id	: GenuineIntel
model name	: Intel(R) Xeon(R) CPU E5-2680 v4 @ 2.40GHz
cpu MHz		: 2400.000
physical id	: 0
core id		: 1
flags		: fpu vme de pse tsc msr pae mce hypervisor
`

const mountsFixture = `/dev/sda1 / ext4 rw,relatime 0 0
proc /proc proc rw 0 0
sysfs /sys sysfs rw 0 0
tmpfs /run tmpfs rw 0 0
/dev/sdb1 /var/lib/nanmonee\040data ext4 rw 0 0
/dev/sda1 /mnt/dup ext4 rw 0 0
/dev/sdc1 /mnt/missing ext4 rw 0 0
`

func TestParseStatUsesTheAggregateLine(t *testing.T) {
	first, ok := parseStat(statFixtureV1)
	if !ok {
		t.Fatal("expected the aggregate cpu line to parse")
	}
	if first.total != 1000 {
		t.Fatalf("total = %d, want 1000", first.total)
	}
	if first.idle != 800 {
		t.Fatalf("idle = %d, want 800", first.idle)
	}
	if percent := first.percent(); percent != 20 {
		t.Fatalf("average percent = %v, want 20", percent)
	}
}

func TestParseStatRejectsMalformedInput(t *testing.T) {
	for name, content := range map[string]string{
		"empty":       "",
		"no cpu line": "intr 1 2 3\n",
		"short":       "cpu 1 2\n",
		"not numbers": "cpu a b c d e\n",
		"zero total":  "cpu 0 0 0 0 0\n",
	} {
		if _, ok := parseStat(content); ok {
			t.Fatalf("%s: malformed stat parsed", name)
		}
	}
}

func TestCollectorTurnsCountersIntoARate(t *testing.T) {
	root := useFixtures(t)
	writeFile(t, root, "proc/stat", statFixtureV1)
	writeFile(t, root, "proc/uptime", "12345.67 1000.00\n")

	collector := New("0.11.0-test", "v1.14.4", "c005f353")
	first := collector.Sample()
	if first.Usage.CPUPercent != 20 {
		t.Fatalf("first sample cpu = %v, want the average since boot", first.Usage.CPUPercent)
	}

	// Between the two fixtures the CPU spent 200 busy and 600 idle ticks:
	// 25% busy over the interval.
	writeFile(t, root, "proc/stat", statFixtureV2)
	second := collector.Sample()
	if second.Usage.CPUPercent != 25 {
		t.Fatalf("second sample cpu = %v, want 25", second.Usage.CPUPercent)
	}
	if second.UptimeSeconds != 12345 {
		t.Fatalf("uptime = %d, want 12345", second.UptimeSeconds)
	}
	if second.Protocol != ReportProtocol || second.AgentVersion != "0.11.0-test" {
		t.Fatalf("sample identity = %+v", second)
	}
}

func TestSampleReadsSystemConfigurationAndUsage(t *testing.T) {
	root := useFixtures(t)
	writeFile(t, root, "proc/stat", statFixtureV1)
	writeFile(t, root, "proc/uptime", "3600.00 0.00\n")
	writeFile(t, root, "proc/cpuinfo", cpuinfoFixture)
	writeFile(t, root, "proc/meminfo", meminfoFixture)
	writeFile(t, root, "proc/loadavg", "0.52 0.58 0.59 2/123 4567\n")
	writeFile(t, root, "proc/sys/kernel/osrelease", "6.1.0-30-amd64\n")
	writeFile(t, root, "proc/self/statm", "1000 250 100 1 0 0 0\n")
	writeFile(t, root, "proc/self/status", "Name:\tnanmonee-node\nThreads:\t14\n")
	writeFile(t, root, "etc/os-release", `NAME="Debian GNU/Linux"
VERSION="13 (trixie)"
PRETTY_NAME="Debian GNU/Linux 13 (trixie)"
`)
	writeFile(t, root, "sys/class/dmi/id/product_name", "KVM\n")
	writeFile(t, root, "proc/mounts", mountsFixture)
	writeFile(t, root, "dockerenv", "")

	snapshot := New("0.11.0-test", "v1.14.4", "c005f353").Sample()

	if snapshot.System.OS != "Debian GNU/Linux 13 (trixie)" {
		t.Fatalf("os = %q", snapshot.System.OS)
	}
	if snapshot.System.Kernel != "6.1.0-30-amd64" {
		t.Fatalf("kernel = %q", snapshot.System.Kernel)
	}
	if snapshot.System.Arch == "" {
		t.Fatal("arch is empty")
	}
	if snapshot.System.CPU.Model != "Intel(R) Xeon(R) CPU E5-2680 v4 @ 2.40GHz" {
		t.Fatalf("cpu model = %q", snapshot.System.CPU.Model)
	}
	if snapshot.System.CPU.Cores != 3 || snapshot.System.CPU.PhysicalCores != 2 {
		t.Fatalf("cores = %d/%d, want 3 logical and 2 physical",
			snapshot.System.CPU.Cores, snapshot.System.CPU.PhysicalCores)
	}
	if snapshot.System.CPU.MHz != 2400 {
		t.Fatalf("mhz = %d", snapshot.System.CPU.MHz)
	}
	if snapshot.System.Virtualization != "container" {
		t.Fatalf("virtualization = %q", snapshot.System.Virtualization)
	}
	if snapshot.System.MemoryTotal != 8000000*1024 {
		t.Fatalf("memory total = %d", snapshot.System.MemoryTotal)
	}
	if snapshot.System.SwapTotal != 2000000*1024 {
		t.Fatalf("swap total = %d", snapshot.System.SwapTotal)
	}
	if snapshot.Usage.Memory.Available != 2000000*1024 {
		t.Fatalf("memory available = %d", snapshot.Usage.Memory.Available)
	}
	if snapshot.Usage.Memory.Used != (8000000-2000000)*1024 {
		t.Fatalf("memory used = %d", snapshot.Usage.Memory.Used)
	}
	if snapshot.Usage.Swap.Used != 500000*1024 {
		t.Fatalf("swap used = %d", snapshot.Usage.Swap.Used)
	}
	if snapshot.Usage.Load.One != 0.52 || snapshot.Usage.Load.Five != 0.58 || snapshot.Usage.Load.Fifteen != 0.59 {
		t.Fatalf("load = %+v", snapshot.Usage.Load)
	}
	if snapshot.Usage.Process.Threads != 14 {
		t.Fatalf("threads = %d", snapshot.Usage.Process.Threads)
	}
	if snapshot.Usage.Process.RSSBytes <= 0 {
		t.Fatalf("rss = %d", snapshot.Usage.Process.RSSBytes)
	}
	if snapshot.Usage.Process.Goroutines < 1 {
		t.Fatalf("goroutines = %d", snapshot.Usage.Process.Goroutines)
	}
	// Mount points are stat'd on the real host, so the fixture list resolves to
	// whatever exists here. The invariant that matters is that an empty list
	// always carries a reason and a populated one never does.
	for _, disk := range snapshot.Usage.Disk {
		if disk.Total <= 0 || disk.Used < 0 || disk.Used > disk.Total {
			t.Fatalf("implausible disk reading: %+v", disk)
		}
	}
	if (len(snapshot.Usage.Disk) == 0) != (snapshot.Usage.DiskError != "") {
		t.Fatalf("disk = %+v, error = %q", snapshot.Usage.Disk, snapshot.Usage.DiskError)
	}
}

func TestMissingSourcesDegradeInsteadOfFailing(t *testing.T) {
	useFixtures(t)
	snapshot := New("0.11.0-test", "v1.14.4", "c005f353").Sample()

	if snapshot.System.CPU.Cores < 1 {
		t.Fatalf("cores = %d, want the runtime fallback", snapshot.System.CPU.Cores)
	}
	if snapshot.Usage.Memory.Total != 0 || snapshot.Usage.CPUPercent != 0 {
		t.Fatalf("expected zero readings, got %+v", snapshot.Usage)
	}
	if snapshot.UptimeSeconds != 0 {
		t.Fatalf("uptime = %d", snapshot.UptimeSeconds)
	}
}

func TestParseMeminfoWithoutMemAvailableUsesReclaimablePages(t *testing.T) {
	content := "MemTotal: 1000 kB\nMemFree: 100 kB\nBuffers: 100 kB\nCached: 200 kB\nSwapTotal: 0 kB\nSwapFree: 0 kB\n"
	info := parseMeminfo(content)
	if info.used.Available != 400*1024 {
		t.Fatalf("available = %d", info.used.Available)
	}
	if info.used.Used != 600*1024 {
		t.Fatalf("used = %d", info.used.Used)
	}
	if info.swapUsed.Total != 0 || info.swapUsed.Used != 0 {
		t.Fatalf("swap = %+v", info.swapUsed)
	}
}

func TestParseMeminfoClampsImpossibleValues(t *testing.T) {
	info := parseMeminfo("MemTotal: 1000 kB\nMemAvailable: 5000 kB\nSwapTotal: 100 kB\nSwapFree: 500 kB\n")
	if info.used.Available != 1000*1024 || info.used.Used != 0 {
		t.Fatalf("memory = %+v", info.used)
	}
	if info.swapUsed.Used != 0 || info.swapUsed.Available != 100*1024 {
		t.Fatalf("swap = %+v", info.swapUsed)
	}
}

func TestParseMountsSkipsPseudoFilesystemsAndDeduplicates(t *testing.T) {
	mounts := parseMounts(mountsFixture)
	want := []string{"/", `/var/lib/nanmonee data`, "/mnt/dup", "/mnt/missing"}
	if len(mounts) != len(want) {
		t.Fatalf("mounts = %v, want %v", mounts, want)
	}
	for index := range want {
		if mounts[index] != want[index] {
			t.Fatalf("mounts[%d] = %q, want %q", index, mounts[index], want[index])
		}
	}
}

func TestUnescapeMountHandlesOctalEscapes(t *testing.T) {
	if got := unescapeMount("/var/lib/nanmonee\\040data\\011x"); got != "/var/lib/nanmonee data\tx" {
		t.Fatalf("unescape = %q", got)
	}
	if got := unescapeMount("/plain"); got != "/plain" {
		t.Fatalf("unescape = %q", got)
	}
}

func TestParseCPUInfoWithoutCoreIDsFallsBackToZero(t *testing.T) {
	info := parseCPUInfo("processor\t: 0\nmodel name\t: Test CPU\n")
	if info.logical != 1 || info.physical != 0 || info.model != "Test CPU" {
		t.Fatalf("info = %+v", info)
	}
}

func TestParseLoadavgAndUptimeRejectGarbage(t *testing.T) {
	if load := parseLoadavg("garbage"); load != (Load{}) {
		t.Fatalf("load = %+v", load)
	}
	if _, ok := parseUptime("nope"); ok {
		t.Fatal("garbage uptime parsed")
	}
	if value, ok := parseUptime("42.5 1.0"); !ok || value != 42.5 {
		t.Fatalf("uptime = %v, %v", value, ok)
	}
}

func TestReadVirtualizationBareMetalAndHypervisor(t *testing.T) {
	root := useFixtures(t)
	if got := readVirtualization("processor\t: 0\nflags\t\t: fpu vme\n"); got != "none" {
		t.Fatalf("bare metal = %q", got)
	}
	// A hypervisor flag with no DMI and no container marker still reports a
	// hypervisor, never a guessed vendor.
	if got := readVirtualization("processor\t: 0\nflags\t\t: fpu hypervisor\n"); got != "hypervisor" {
		t.Fatalf("unknown hypervisor = %q", got)
	}
	writeFile(t, root, "sys/class/dmi/id/product_name", "VMware Virtual Platform\n")
	if got := readVirtualization("processor\t: 0\nflags\t\t: fpu hypervisor\n"); got != "vmware" {
		t.Fatalf("vmware = %q", got)
	}
}
