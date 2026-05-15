package middleware

import (
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"
)

// Network packet data structure
type Packet struct {
	Source     string `json:"src"`
	Dest       string `json:"dst"`
	Type       string `json:"type"`
	Size       int    `json:"size"`
	Data       string `json:"data"`
	Plaintext  string `json:"plaintext"`
}

// Packet capture and timing engine
type Sniffer struct {
	CapturedPackets []Packet
	stateLock       sync.Mutex
	SignalDone      chan bool
	SilenceTimeout  time.Duration
	inactivityTimer *time.Timer
}

// Initialize sniffer with timeout
func NewSniffer(timeout time.Duration) *Sniffer {
	return &Sniffer{
		CapturedPackets: []Packet{},
		SignalDone:      make(chan bool, 1),
		SilenceTimeout:  timeout,
	}
}

// Start packet collection server
func (sniffer *Sniffer) Start() {
	http.HandleFunc("/capture/packet", func(response http.ResponseWriter, request *http.Request) {
		var incomingPacket Packet
		json.NewDecoder(request.Body).Decode(&incomingPacket)
		
		sniffer.stateLock.Lock()
		sniffer.CapturedPackets = append(sniffer.CapturedPackets, incomingPacket)
		
		// Step: Reset inactivity timer
		if sniffer.inactivityTimer != nil {
			sniffer.inactivityTimer.Stop()
		}
		
		fmt.Printf("[SNIFFER] Packet captured. Resetting %v timer...\n", sniffer.SilenceTimeout)
		sniffer.inactivityTimer = time.AfterFunc(sniffer.SilenceTimeout, func() {
			fmt.Printf("[SNIFFER] %v silence detected. Triggering completion.\n", sniffer.SilenceTimeout)
			sniffer.SignalDone <- true
		})
		
		sniffer.stateLock.Unlock()
		response.WriteHeader(http.StatusOK)
	})

	// Run capture listener
	go http.ListenAndServe(":9000", nil)
}
