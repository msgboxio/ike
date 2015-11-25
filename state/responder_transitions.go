package state

func ResponderTransitions(h FsmHandler) map[Event][]Transition {
	return map[Event][]Transition{
		MSG_INIT: []Transition{
			// Received INIT reply
			Transition{
				source: STATE_IDLE,
				dest:   STATE_INIT,
				check:  h.CheckInit,
				action: h.SendInit,
			},
		},
		INIT_FAIL: []Transition{
			// Cannot send message or Cannot build message
			Transition{
				source: STATE_IDLE,
				dest:   STATE_FINISHED,
			},
		},
		TIMEOUT: []Transition{
			// Did not recive Auth within timeout
			Transition{
				source: STATE_INIT,
				dest:   STATE_IDLE,
			},
			Transition{
				source: STATE_AUTH,
				dest:   STATE_IDLE,
			},
		},
		MSG_AUTH: []Transition{
			// Received INIT reply
			Transition{
				source: STATE_INIT,
				dest:   STATE_MATURE,
				check:  h.CheckAuth,
				action: h.SendAuth,
			},
		},
		AUTH_FAIL: []Transition{
			// Unable to parse / Handle reply
			Transition{
				source: STATE_INIT,
				dest:   STATE_FINISHED,
			},
		},
	}
}
