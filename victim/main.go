package main

import (
	"victim-app/client"
	"victim-app/core"
	"victim-app/middleware"
)

func main() {
	// Initialize configuration
	core.LoadConfig()
	conf := core.Config

	// Initialize logger
	l := middleware.NewSnifferLogger(conf.SnifferURL, conf.VictimIP, conf.ServerIP)

	// Initialize client
	vClient := client.NewVictimClient(conf.ServerURL, conf.TargetURL, l)

	// Run simulation
	vClient.RunSimulation()
}
