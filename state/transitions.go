package state

import (
	"context"
	"fmt"

	"github.com/msgboxio/log"
)

type Event uint32
type State uint32

type StateEvent struct {
	Event
	Data interface{}
}

type CheckEvent func(interface{}) StateEvent
type Action func() StateEvent

type Transition struct {
	Dest State
	CheckEvent
	Action
}

func key(ev Event, state State) uint64 {
	return (uint64(ev) << 32) | uint64(state)
}

// UserTransitions is specified by client
type UserTransitions map[Event]Transition

// key is event < 32 | source state
type transitions map[uint64]Transition

func (trs transitions) addTransitions(t2 map[State]UserTransitions) {
	for state, _map := range t2 {
		for event, tr := range _map {
			key := key(event, state)
			if oldTr, ok := trs[key]; ok {
				panic(fmt.Sprintf("duplicate transition for event %v: old transition %+v, new transition %+v", event, tr, oldTr))
			}
			trs[key] = tr
		}
	}
}

type Fsm struct {
	transitions
	State

	messages chan StateEvent

	context.Context
	cancel context.CancelFunc
}

func NewFsm(inputs ...map[State]UserTransitions) *Fsm {
	trs := make(transitions)
	for _, tr := range inputs {
		trs.addTransitions(tr)
	}
	cxt, cancel := context.WithCancel(context.Background())
	return &Fsm{
		transitions: trs,
		State:       STATE_IDLE,
		messages:    make(chan StateEvent, 10),
		Context:     cxt,
		cancel:      cancel,
	}
}

func (f *Fsm) Event(m StateEvent) {
	f.messages <- m
}

func (f *Fsm) Run() {
	for {
		if m, ok := <-f.messages; ok {
			f.handleEvent(m)
			if f.State == STATE_FINISHED {
				break
			}
		}
	}
	close(f.messages)
	f.cancel()
}

func (f *Fsm) runTransition(t Transition, m StateEvent) (s StateEvent) {
	if t.CheckEvent != nil {
		if err := t.CheckEvent(m.Data); err.Data != nil {
			log.V(1).Infof("Check Error: %s", err.Data)
			// dont transition, handle error in same state
			f.Event(err)
			return err
		}
	}
	if t.Action != nil {
		if err := t.Action(); err.Data != nil {
			log.V(1).Infof("Action Error: %s", err.Data)
			// dont transition, handle error in same state
			f.Event(err)
			return err
		}
	}
	return
}

func (f *Fsm) handleEvent(m StateEvent) {
	t, ok := f.transitions[key(m.Event, f.State)]
	if !ok {
		log.V(1).Infof("Ignoring event %s, in State %s", m.Event, f.State)
		return
	}
	log.V(1).Infof("Run: Event %s, in State %s", m.Event, f.State)
	if err := f.runTransition(t, m); err.Data != nil {
		return
	}
	// execute entry action for new state, it does not directly cause state changes
	tEntry, ok := f.transitions[key(ENTRY_EVENT, t.Dest)]
	if ok {
		log.V(1).Infof("Run: Event %s, for State %s", ENTRY_EVENT, t.Dest)
		if err := f.runTransition(tEntry, m); err.Data != nil {
			return
		}
	}
	// change state
	log.V(1).Infof("Change: Previous %s, Current %s", f.State, t.Dest)
	f.State = t.Dest
	return
}
