package state

func InitiatorTransitions(h FsmHandler) map[Event][]Transition {
	return map[Event][]Transition{
		SMI_START: []Transition{
			// Send INIT, set timeout
			Transition{
				Source: STATE_IDLE,
				Dest:   STATE_INIT,
				Action: h.SendInit,
			},
		},
		MSG_INIT: []Transition{
			// Received INIT reply
			Transition{
				Source:     STATE_INIT,
				Dest:       STATE_AUTH,
				CheckEvent: h.HandleIkeSaInit,
				Action:     h.SendAuth,
			},
		},
		INIT_FAIL: []Transition{
			// Cannot send message or Cannot build message
			Transition{
				Source: STATE_INIT,
				Dest:   STATE_FINISHED,
			},
		},
		TIMEOUT: []Transition{
			// Did not recive reply within timeout
			Transition{
				Source: STATE_INIT,
				Dest:   STATE_IDLE,
				Action: h.StartRetryTimeout,
			},
			Transition{
				Source: STATE_AUTH,
				Dest:   STATE_IDLE,
				Action: h.StartRetryTimeout,
			},
		},
		MSG_AUTH: []Transition{
			// Received AUTH reply
			Transition{
				Source:     STATE_AUTH,
				Dest:       STATE_AUTH,
				CheckEvent: h.HandleIkeAuth,
			},
		},
		SUCCESS: []Transition{
			// AUTH SUCCESS
			Transition{
				Source:     STATE_AUTH,
				Dest:       STATE_MATURE,
				CheckEvent: h.CheckSa,
				Action:     h.InstallSa,
			},
		},
		AUTH_FAIL: []Transition{
			// Unable to parse / Handle reply
			Transition{
				Source: STATE_AUTH,
				Dest:   STATE_FINISHED,
			},
		},
	}
}
