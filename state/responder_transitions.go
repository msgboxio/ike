package state

func ResponderTransitions(h FsmHandler) map[State]UserTransitions {
	return map[State]UserTransitions{
		STATE_IDLE: UserTransitions{
			SMI_START: Transition{
				Dest: STATE_START,
			},
		},
		STATE_START: UserTransitions{
			MSG_INIT: Transition{
				CheckEvent: h.HandleIkeSaInit,
				Action:     h.SendInit,
				Dest:       STATE_INIT,
			},
			INIT_FAIL: Transition{
				Dest: STATE_IDLE,
			},
		},
		STATE_INIT: UserTransitions{
			MSG_AUTH: Transition{
				CheckEvent: h.HandleIkeAuth,
				Action:     h.SendAuth,
				Dest:       STATE_AUTH,
			},
			AUTH_FAIL: Transition{
				Dest: STATE_IDLE,
			},
		},
		STATE_AUTH: UserTransitions{
			ENTRY_EVENT: Transition{
				CheckEvent: h.CheckSa,
				Action:     h.InstallSa,
				Dest:       STATE_MATURE,
			},
		},
		STATE_MATURE:   UserTransitions{},
		STATE_FINISHED: UserTransitions{},
	}
}
