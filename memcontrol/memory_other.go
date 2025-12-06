//go:build !linux

package memcontrol

// getTotalSystemMemory returns 0 on non-Linux systems.
// Budget will use default profile.
func getTotalSystemMemory() uint64 {
	return 0
}
