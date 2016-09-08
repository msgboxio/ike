package state

func ResponderTransitions(h FsmHandler) map[Event][]Transition {
	return map[Event][]Transition{
		MSG_INIT: []Transition{
			// Received INIT reply
			Transition{
				Source:     STATE_IDLE,
				Dest:       STATE_INIT,
				CheckEvent: h.HandleIkeSaInit,
				Action:     h.SendInit,
			},
		},
		INIT_FAIL: []Transition{
			// Cannot send message or Cannot build message
			Transition{
				Source: STATE_IDLE,
				Dest:   STATE_FINISHED,
			},
		},
		TIMEOUT: []Transition{
			// Did not recive Auth within timeout
			Transition{
				Source: STATE_INIT,
				Dest:   STATE_IDLE,
			},
			Transition{
				Source: STATE_AUTH,
				Dest:   STATE_IDLE,
			},
		},
		MSG_AUTH: []Transition{
			// Received AUTH
			Transition{
				Source:     STATE_INIT,
				Dest:       STATE_AUTH,
				CheckEvent: h.HandleIkeAuth,
				Action:     h.SendAuth,
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
				Source:     STATE_INIT,
				Dest:       STATE_FINISHED,
				CheckEvent: h.CheckError,
			},
		},
	}
}
