package ike

import (
	"math/rand"
	"time"
)

// from Kubernets

// Jitter returns a time.Duration between duration and duration + maxFactor * duration,
// to allow clients to avoid converging on periodic behavior.  If maxFactor is 0.0, a
// suggested default value will be chosen.
func Jitter(duration time.Duration, maxFactor float64) time.Duration {
	if maxFactor == 0.0 {
		maxFactor = 1.0
	}
	return duration + time.Duration(rand.Float64()*maxFactor*float64(duration))
}
