//go:build !agent

package run

import "embed"

//go:embed all:agents
var agentFiles embed.FS
