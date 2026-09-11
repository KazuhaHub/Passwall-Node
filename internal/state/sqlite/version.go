package sqlite

import (
	"encoding/binary"
	"fmt"

	"github.com/KazuhaHub/passwall-node/protocol"
)

// SQLite INTEGER is signed while protocol versions are uint64. Fixed-width
// big-endian blobs preserve every wire value without an accidental 2^63 cap.
func encodeUint64(value uint64) []byte {
	b := make([]byte, 8)
	binary.BigEndian.PutUint64(b, value)
	return b
}

func decodeUint64(value []byte) (uint64, error) {
	if len(value) != 8 {
		return 0, fmt.Errorf("uint64 state value has length %d, want 8", len(value))
	}
	return binary.BigEndian.Uint64(value), nil
}

func decodeVersion(epoch, version []byte) (protocol.Version, error) {
	e, err := decodeUint64(epoch)
	if err != nil {
		return protocol.Version{}, fmt.Errorf("decode epoch: %w", err)
	}
	v, err := decodeUint64(version)
	if err != nil {
		return protocol.Version{}, fmt.Errorf("decode version: %w", err)
	}
	return protocol.Version{Epoch: e, Version: v}, nil
}
