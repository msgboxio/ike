package state

import "github.com/msgboxio/log"

type Event uint32
type State uint32

type StateEvent struct {
	Event
	Data interface{}
}

type CheckEvent func(interface{}) StateEvent
type Action func() StateEvent

type Transition struct {
	Source, Dest State
	CheckEvent
	Action
}

func AddTransitions(t1, t2 map[Event][]Transition) map[Event][]Transition {
	trs := make(map[Event][]Transition)
	for ev, transitions := range t1 {
		trs[ev] = transitions
	}
	// TODO - this simply overwrites for now
	for ev, transitions := range t2 {
		trs[ev] = transitions
	}
	return trs
}

type Fsm struct {
	transitions map[Event][]Transition
	State

	messages chan StateEvent
}

func NewFsm(trs map[Event][]Transition) *Fsm {
	return &Fsm{
		transitions: trs,
		State:       STATE_IDLE,
		messages:    make(chan StateEvent, 10),
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
	f.transitions[FINISHED][0].Action()
}

func (f *Fsm) handleEvent(m StateEvent) {
	transitions, ok := f.transitions[m.Event]
	if !ok {
		log.V(1).Infof("Ignoring event %s, in State %s", m.Event, f.State)
		return
	}
	log.V(1).Infof("Run: Event %s, in State %s", m.Event, f.State)
	for _, t := range transitions {
		if t.Source == f.State {
			if t.CheckEvent != nil {
				if err := t.CheckEvent(m.Data); err.Data != nil {
					log.V(1).Infof("Check Error: %s, in State %s", err.Data, f.State)
					// dont do transition, handle error in same state
					f.Event(err)
					return
				}
			}
			if t.Action != nil {
				if err := t.Action(); err.Data != nil {
					log.V(1).Infof("Action Error: %s, in State %s", err.Data, f.State)
					// dont do transition, handle error in same state
					f.Event(err)
					return
				}
			}
			// change state
			log.V(1).Infof("Change: Previous %s, Current %s", f.State, t.Dest)
			f.State = t.Dest
			return
		}
	}
}
