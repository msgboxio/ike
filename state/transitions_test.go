package state

import (
	"errors"
	"reflect"
	"sync"
	"testing"
)

func TestTransitions(t *testing.T) {
	var wg sync.WaitGroup

	trs := map[State]UserTransitions{
		STATE_IDLE: UserTransitions{
			MSG_INIT: Transition{
				Dest:       STATE_INIT,
				CheckEvent: func(interface{}) (s StateEvent) { wg.Done(); return },
				Action:     func() (s StateEvent) { wg.Done(); return },
			},
		},
		STATE_INIT: UserTransitions{
			MSG_AUTH: Transition{
				Dest: STATE_AUTH,
				CheckEvent: func(interface{}) (s StateEvent) {
					s.Data = errors.New("FF")
					s.Event = AUTH_FAIL
					wg.Done()
					return
				},
				Action: func() (s StateEvent) { wg.Done(); return },
			},
			AUTH_FAIL: Transition{
				Dest:       STATE_IDLE,
				CheckEvent: func(interface{}) (s StateEvent) { wg.Done(); return },
				Action:     func() (s StateEvent) { wg.Done(); return },
			},
		},
	}
	f := NewFsm(trs)
	// go f.Run()

	wg.Add(2)
	f.PostEvent(StateEvent{Event: MSG_INIT})
	wg.Wait()
	if f.State != STATE_INIT {
		t.Fail()
	}

	wg.Add(3)
	f.PostEvent(StateEvent{Event: MSG_AUTH})
	wg.Wait()
	if f.State != STATE_IDLE {
		t.Fail()
	}
}

// tests
// 1. finishes on reaching FINISHED state
// 2. runs Entry action of the finished state
// 3. does not run entry action of the IDLE state
func TestTransitionsFinish(t *testing.T) {
	events := []int{}

	trs := map[State]UserTransitions{
		STATE_IDLE: UserTransitions{
			MSG_INIT: Transition{
				Dest:       STATE_FINISHED,
				CheckEvent: func(interface{}) (s StateEvent) { events = append(events, 1); return },
				Action:     func() (s StateEvent) { events = append(events, 2); return },
			},
		},
		STATE_FINISHED: UserTransitions{
			ENTRY_EVENT: Transition{
				Action: func() (s StateEvent) { events = append(events, 3); return },
			},
		},
	}

	f := NewFsm(trs)
	// go f.Run()

	f.PostEvent(StateEvent{Event: MSG_INIT})
	// <-f.Done()
	if !reflect.DeepEqual(events, []int{1, 2, 3}) {
		t.Error("unexpected", events)
	}
}
