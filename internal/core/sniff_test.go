package core

import (
	"github.com/KazuhaHub/passwall-protocol/protocol/conformance"
	"testing"
)

func TestDestinationSniffingConformance(t *testing.T) {
	for _, v := range conformance.SniffingVectors {
		t.Run(v.Name, func(t *testing.T) {
			got := CheckDestinationSniffing(v.Sniffing)
			if got.Sufficient != v.Sufficient || got.Inject != v.Inject || got.Reason != v.Reason {
				t.Fatalf("sniffing = %#v, want sufficient=%v inject=%v reason=%q", got, v.Sufficient, v.Inject, v.Reason)
			}
		})
	}
}
