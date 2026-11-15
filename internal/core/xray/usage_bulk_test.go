package xray

import "os"

// usageLoadEnv switches on the per-site usage load measurement and the full
// bulk correctness run. Off by default: neither may start on a developer
// machine by accident.
const usageLoadEnv = "PSP_TEST_USAGE_LOAD"

// bulkConnections is how many connections the receiver's bulk correctness test
// sends: a small number by default, the full 2000 only with the load switch.
func bulkConnections() int {
	if os.Getenv(usageLoadEnv) == "1" {
		return 2000
	}
	return 100
}
