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
			DELETE_IKE_SA: Transition{
				Dest: STATE_FINISHED,
			},
		},
		STATE_INIT: UserTransitions{
			MSG_AUTH: Transition{
				CheckEvent: h.HandleIkeAuth,
				Action:     h.SendAuth,
				Dest:       STATE_AUTH,
			},
			AUTH_FAIL: Transition{
				CheckEvent: h.CheckError,
				Dest:       STATE_FINISHED,
			},
			DELETE_IKE_SA: Transition{
				Dest: STATE_FINISHED,
			},
		},
		STATE_AUTH: UserTransitions{
			ENTRY_EVENT: Transition{
				CheckEvent: h.CheckSa,
				Action:     h.InstallSa,
			},
			SUCCESS: Transition{
				Dest: STATE_MATURE,
			},
			DELETE_IKE_SA: Transition{
				Dest: STATE_FINISHED,
			},
		},
		STATE_MATURE:   UserTransitions{},
		STATE_FINISHED: UserTransitions{},
	}
}
