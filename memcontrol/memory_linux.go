//go:build linux

package memcontrol

import (
	"os"
	"strconv"
	"strings"
)

// getTotalSystemMemory returns the effective memory limit in bytes on Linux.
// It returns the MINIMUM of:
// 1. Cgroup memory limit (if running in container/cgroup)
// 2. Physical RAM from /proc/meminfo
//
// This ensures correct behavior under:
// - Docker/Podman containers with --memory flag
// - systemd-run --scope -p MemoryMax=X
// - Kubernetes memory limits
// - LXC/LXD containers
func getTotalSystemMemory() uint64 {
	cgroupLimit := getCgroupMemoryLimit()
	physicalMem := getPhysicalMemory()

	// If cgroup limit is set and valid, use the minimum
	if cgroupLimit > 0 && cgroupLimit < physicalMem {
		return cgroupLimit
	}

	return physicalMem
}

// getCgroupMemoryLimit returns the cgroup memory limit, or 0 if not constrained.
// Supports both cgroup v2 (unified) and cgroup v1 (legacy).
func getCgroupMemoryLimit() uint64 {
	// Try cgroup v2 first (unified hierarchy)
	// Path: /sys/fs/cgroup/memory.max
	if data, err := os.ReadFile("/sys/fs/cgroup/memory.max"); err == nil {
		content := strings.TrimSpace(string(data))
		// "max" means no limit
		if content != "max" {
			if limit, err := strconv.ParseUint(content, 10, 64); err == nil && limit > 0 {
				return limit
			}
		}
	}

	// Try cgroup v1 (legacy hierarchy)
	// Path: /sys/fs/cgroup/memory/memory.limit_in_bytes
	if data, err := os.ReadFile("/sys/fs/cgroup/memory/memory.limit_in_bytes"); err == nil {
		content := strings.TrimSpace(string(data))
		if limit, err := strconv.ParseUint(content, 10, 64); err == nil {
			// cgroup v1 uses a very large number (PAGE_COUNTER_MAX) to indicate no limit
			// Typically 9223372036854771712 or similar (close to int64 max)
			// If limit is > 1 exabyte, consider it "no limit"
			const exabyte = 1 << 60
			if limit > 0 && limit < exabyte {
				return limit
			}
		}
	}

	// Also check the container-specific paths (Docker, Kubernetes)
	// Some containers mount cgroup at different locations
	containerPaths := []string{
		"/sys/fs/cgroup/memory.max",                     // cgroup v2 (already checked above, but retry)
		"/sys/fs/cgroup/memory/memory.limit_in_bytes",   // cgroup v1 (already checked)
		"/proc/1/root/sys/fs/cgroup/memory.max",         // Container namespace
		"/proc/1/root/sys/fs/cgroup/memory/memory.limit_in_bytes",
	}

	for _, path := range containerPaths {
		if data, err := os.ReadFile(path); err == nil {
			content := strings.TrimSpace(string(data))
			if content != "max" {
				if limit, err := strconv.ParseUint(content, 10, 64); err == nil {
					const exabyte = 1 << 60
					if limit > 0 && limit < exabyte {
						return limit
					}
				}
			}
		}
	}

	return 0 // No cgroup limit detected
}

// getPhysicalMemory returns total physical RAM from /proc/meminfo.
func getPhysicalMemory() uint64 {
	data, err := os.ReadFile("/proc/meminfo")
	if err != nil {
		return 0
	}

	// Parse MemTotal line (format: "MemTotal:    12345678 kB")
	lines := strings.Split(string(data), "\n")
	for _, line := range lines {
		if strings.HasPrefix(line, "MemTotal:") {
			fields := strings.Fields(line)
			// Verify we have value and unit, and unit is kB
			if len(fields) >= 3 && strings.EqualFold(fields[2], "kb") {
				kb, err := strconv.ParseUint(fields[1], 10, 64)
				if err == nil {
					return kb * 1024 // Convert KB to bytes
				}
			}
			break
		}
	}

	return 0
}
