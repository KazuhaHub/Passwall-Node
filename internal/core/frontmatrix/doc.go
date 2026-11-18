// Package frontmatrix holds the real-core test of SNI fronts (transit.sni.v1):
// an Xray core compiled by this repository's own compiler shares one TCP port
// among its own REALITY listeners, a raw relay to a landing core, an incoming
// link and an external default site, and real Xray clients, the node's own
// telemetry and its prober go through it. It has no production code, and every
// test skips unless Xray binaries are named in the environment.
package frontmatrix
