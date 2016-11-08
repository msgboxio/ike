package state

import (
	"fmt"
	"time"

	"github.com/Sirupsen/logrus"
)

// TODO -
const RETRY_TIMEOUT = 2 * time.Second

type CheckEvent func(*StateEvent) *StateEvent
type Action func(*StateEvent) *StateEvent

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

// key is [event < 32 | source state]
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

	messages chan *StateEvent
	log      *logrus.Logger
}

func NewFsm(log *logrus.Logger, inputs ...map[State]UserTransitions) *Fsm {
	trs := make(transitions)
	for _, tr := range inputs {
		trs.addTransitions(tr)
	}
	return &Fsm{
		transitions: trs,
		State:       STATE_IDLE,
		messages:    make(chan *StateEvent, 10),
		log:         log,
	}
}

func (f *Fsm) PostEvent(m *StateEvent) {
	f.messages <- m
}

func (f *Fsm) Events() <-chan *StateEvent { return f.messages }

func (f *Fsm) CloseFsm() {
	close(f.messages)
	if f.State != STATE_FINISHED {
		// f.log.Warningf("Fsm Closed in State %s", f.State)
		// draining the queue by sleeping seems to work
		time.Sleep(time.Millisecond)
	}
}

// runTransition runs the CheckEvent callback & then Action
// in both cases it stops on error and posts the Error event
func (f *Fsm) runTransition(t Transition, m *StateEvent) (evt *StateEvent) {
	if t.CheckEvent != nil {
		if evt = t.CheckEvent(m); evt != nil && evt.Error != nil {
			f.log.Warningf("Check Error: %s for Event %s, in State %s", evt.Error, m.Event, f.State)
			// dont transition, handle error in same state
			f.PostEvent(evt)
			return evt
		}
	}
	if t.Action != nil {
		if evt = t.Action(m); evt != nil && evt.Error != nil {
			f.log.Warningf("Action Error: %s for Event %s, in State %s", evt.Error, m.Event, f.State)
			// dont transition, handle error in same state
			f.PostEvent(evt)
			return evt
		}
	}
	return
}

func (f *Fsm) runEntryEvent(t Transition, m *StateEvent) (evt *StateEvent) {
	// execute entry action for new state, it does not directly cause state changes
	tEntry, ok := f.transitions[key(ENTRY_EVENT, t.Dest)]
	if ok {
		f.log.Infof("Run: Event %s, for State %s", ENTRY_EVENT, t.Dest)
		if evt = f.runTransition(tEntry, m); evt != nil && evt.Error != nil {
			return
		}
	}
	return
}

func (f *Fsm) runTimer() {
	// check if a timeout is configured for the state
	if _, ok := f.transitions[key(TIMEOUT, f.State)]; !ok {
		return
	}
	curState := f.State
	go func() {
		for {
			// TODO - timeout is
			time.Sleep(RETRY_TIMEOUT)
			if f.State != curState {
				// state changed, end the goroutine
				break
			}
			// state is still the same, fire timeout event
			f.PostEvent(&StateEvent{Event: TIMEOUT})
		}
	}()
}

func (f *Fsm) HandleEvent(m *StateEvent) {
	t, ok := f.transitions[key(m.Event, f.State)]
	if !ok {
		f.log.Infof("Ignoring event %s, in State %s", m.Event, f.State)
		return
	}
	f.log.Infof("Run: Event %s, in State %s", m.Event, f.State)
	if evt := f.runTransition(t, m); evt != nil && evt.Error != nil {
		return
	}
	if t.Dest == f.State {
		f.log.Infof("State did not change, Current %s", f.State)
		return
	}
	// ignore STATE_IDLE, not a real state; default
	if t.Dest == STATE_IDLE {
		return
	}
	// legitemate state change
	if evt := f.runEntryEvent(t, m); evt != nil && evt.Error != nil {
		return
	}
	f.log.Infof("Change: Previous %s, Current %s", f.State, t.Dest)
	f.State = t.Dest
	f.runTimer()
	return
}
