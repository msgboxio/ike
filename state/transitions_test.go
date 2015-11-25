package state

import (
	"errors"
	"flag"
	"sync"
	"testing"
)

const (
	E1 Event = iota + 1
	E2
	E3
	EE
)

const (
	S1 State = iota + 1
	S2
	S3
	SE
)

func TestTransitions(t *testing.T) {
	flag.Set("logtostderr", "true")
	flag.Set("v", "1")
	flag.Parse()

	var wg sync.WaitGroup

	trs := map[Event][]Transition{
		E1: []Transition{
			Transition{
				source: STATE_IDLE,
				dest:   S1,
				check:  func(interface{}) (s StateEvent) { wg.Done(); return },
				action: func(interface{}) (s StateEvent) { wg.Done(); return },
			},
		},
		E2: []Transition{
			Transition{
				source: S1,
				dest:   S3,
				check: func(interface{}) (s StateEvent) {
					s.Data = errors.New("FF")
					s.Event = EE
					wg.Done()
					return
				},
				action: func(interface{}) (s StateEvent) { wg.Done(); return },
			},
		},
		EE: []Transition{
			Transition{
				source: S1,
				dest:   SE,
				check:  func(interface{}) (s StateEvent) { wg.Done(); return },
				action: func(interface{}) (s StateEvent) { wg.Done(); return },
			},
		},
	}
	f := NewFsm(trs)
	go f.Run()

	wg.Add(2)
	f.Event(StateEvent{Event: E1})
	wg.Wait()
	if f.state != S1 {
		t.Fail()
	}

	wg.Add(3)
	f.Event(StateEvent{Event: E2})
	wg.Wait()
	if f.state != SE {
		t.Fail()
	}
}
