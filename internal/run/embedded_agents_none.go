//go:build agent

package run

import "embed"

// Agents don't embed other agents.
var agentFiles embed.FS
