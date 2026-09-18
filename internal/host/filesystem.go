package host

import "github.com/KazuhaHub/passwall-node/protocol"

// collectFilesystem measures the filesystem holding the agent's data directory.
//
// ONLY THAT ONE FILESYSTEM IS MEASURED. The operator needs to know whether this
// node is about to run out of room, and the data directory is the only place
// this agent writes. Enumerating the host's mounts would report every loopback
// device, every tmpfs and every snapshot, and bury the one number that matters.
func (c *collector) collectFilesystem(collected *sample) {
	if c.options.DataDir == "" {
		collected.markUnavailable(protocol.UnavailableFilesystemData)
		return
	}
	usage, err := c.statFS(c.options.DataDir)
	if err != nil {
		// A missing data directory is not a missing metric — it is a deployment
		// the agent cannot measure yet. The token says so rather than reporting
		// a zero-capacity filesystem, which reads as a full disk.
		collected.markUnavailable(protocol.UnavailableFilesystemData)
		return
	}
	filesystem := protocol.FilesystemObservation{
		TotalBytes:     usage.TotalBytes,
		AvailableBytes: usage.AvailableBytes,
		ReadOnly:       usage.ReadOnly,
	}
	// Inodes are paired, and both stay nil where the filesystem does not report
	// a meaningful count — a zero would render as "0 of 0 used", which reads as
	// healthy on a filesystem that is in fact out of inodes.
	if usage.TotalInodes != nil && usage.AvailableInodes != nil && *usage.TotalInodes > 0 {
		filesystem.TotalInodes = usage.TotalInodes
		filesystem.AvailableInodes = usage.AvailableInodes
	} else {
		collected.markUnavailable(protocol.UnavailableFilesystemInodes)
	}
	collected.observation.Filesystem = &filesystem
}
