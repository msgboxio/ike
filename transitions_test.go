package ike

import (
	"errors"
	"flag"
	"sync"
	"testing"

	. "github.com/msgboxio/ike/state"
)

func TestTransitions(t *testing.T) {
	flag.Set("logtostderr", "true")
	flag.Set("v", "1")
	flag.Parse()

	var wg sync.WaitGroup

	trs := map[Event][]Transition{
		MSG_INIT: []Transition{
			Transition{
				Source:     STATE_IDLE,
				Dest:       STATE_INIT,
				CheckEvent: func(interface{}) (s StateEvent) { wg.Done(); return },
				Action:     func() (s StateEvent) { wg.Done(); return },
			},
		},
		MSG_AUTH: []Transition{
			Transition{
				Source: STATE_INIT,
				Dest:   STATE_AUTH,
				CheckEvent: func(interface{}) (s StateEvent) {
					s.Data = errors.New("FF")
					s.Event = AUTH_FAIL
					wg.Done()
					return
				},
				Action: func() (s StateEvent) { wg.Done(); return },
			},
		},
		AUTH_FAIL: []Transition{
			Transition{
				Source:     STATE_INIT,
				Dest:       STATE_IDLE,
				CheckEvent: func(interface{}) (s StateEvent) { wg.Done(); return },
				Action:     func() (s StateEvent) { wg.Done(); return },
			},
		},
	}
	f := NewFsm(trs)
	go f.Run()

	wg.Add(2)
	f.Event(StateEvent{Event: MSG_INIT})
	wg.Wait()
	if f.State != STATE_INIT {
		t.Fail()
	}

	wg.Add(3)
	f.Event(StateEvent{Event: MSG_AUTH})
	wg.Wait()
	if f.State != STATE_IDLE {
		t.Fail()
	}
}
