package state

import "github.com/msgboxio/log"

type Event uint32
type State uint32

const ()

type StateEvent struct {
	Event
	Data interface{}
}

type CheckEvent func(interface{}) StateEvent
type Action func() StateEvent

type Transition struct {
	source, dest State
	check        CheckEvent
	action       Action
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
	state       State

	messages chan StateEvent
}

func NewFsm(trs map[Event][]Transition) *Fsm {
	return &Fsm{
		transitions: trs,
		state:       STATE_IDLE,
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
			if f.state == STATE_FINISHED {
				break
			}
		}
	}
	close(f.messages)
	f.transitions[FINISHED][0].action()
}

func (f *Fsm) handleEvent(m StateEvent) {
	transitions, ok := f.transitions[m.Event]
	if !ok {
		log.V(1).Infof("Ignoring event %s, in State %s", m.Event, f.state)
		return
	}
	log.V(1).Infof("Run: Event %s, in State %s", m.Event, f.state)
	for _, t := range transitions {
		if t.source == f.state {
			if t.check != nil {
				if err := t.check(m.Data); err.Data != nil {
					log.V(1).Infof("check Error: %s, in State %s", err.Data, f.state)
					// dont do transition, handle error in same state
					f.Event(err)
					return
				}
			}
			if t.action != nil {
				if err := t.action(); err.Data != nil {
					log.V(1).Infof("Action Error: %s, in State %s", err.Data, f.state)
					// dont do transition, handle error in same state
					f.Event(err)
					return
				}
			}
			// change state
			log.V(1).Infof("Change: Previous %s, Current %s", f.state, t.dest)
			f.state = t.dest
			return
		}
	}
}
