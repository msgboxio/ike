package state

func InitiatorTransitions(h FsmHandler) map[Event][]Transition {
	return map[Event][]Transition{
		SMI_START: []Transition{
			// Send INIT, set timeout
			Transition{
				source: STATE_IDLE,
				dest:   STATE_INIT,
				action: h.SendInit,
			},
		},
		INIT_FAIL: []Transition{
			// Cannot send message or Cannot build message
			Transition{
				source: STATE_INIT,
				dest:   STATE_FINISHED,
			},
		},
		TIMEOUT: []Transition{
			// Did not recive reply within timeout
			Transition{
				source: STATE_INIT,
				dest:   STATE_IDLE,
				action: h.StartRetryTimeout,
			},
			Transition{
				source: STATE_AUTH,
				dest:   STATE_IDLE,
				action: h.StartRetryTimeout,
			},
		},
		MSG_INIT: []Transition{
			// Received INIT reply
			Transition{
				source: STATE_INIT,
				dest:   STATE_AUTH,
				check:  h.CheckInit,
				action: h.SendAuth,
			},
		},
		MSG_AUTH: []Transition{
			// Received INIT reply
			Transition{
				source: STATE_AUTH,
				dest:   STATE_MATURE,
				check:  h.CheckAuth,
				action: h.InstallSa,
			},
		},
		AUTH_FAIL: []Transition{
			// Unable to parse / Handle reply
			Transition{
				source: STATE_AUTH,
				dest:   STATE_FINISHED,
			},
		},
	}
}
