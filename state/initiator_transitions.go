package state

func InitiatorTransitions(h FsmHandler) map[State]UserTransitions {
	return map[State]UserTransitions{
		STATE_IDLE: UserTransitions{
			SMI_START: Transition{
				Dest: STATE_START,
			},
		},
		STATE_START: UserTransitions{
			ENTRY_EVENT: Transition{
				Action: h.SendInit,
			},
			MSG_INIT: Transition{
				CheckEvent: h.HandleIkeSaInit,
				Dest:       STATE_INIT,
			},
			INIT_FAIL: Transition{
				Dest: STATE_FINISHED,
			},
			DELETE_IKE_SA: Transition{
				Dest: STATE_FINISHED,
			},
			FAIL: Transition{
				Action: h.CheckError,
				Dest:   STATE_FINISHED,
			},
			TIMEOUT: Transition{
				Action: h.SendInit,
			},
		},
		STATE_INIT: UserTransitions{
			ENTRY_EVENT: Transition{
				Action: h.SendAuth,
			},
			MSG_AUTH: Transition{
				CheckEvent: h.HandleIkeAuth,
				Dest:       STATE_AUTH,
			},
			AUTH_FAIL: Transition{
				CheckEvent: h.CheckError,
				Dest:       STATE_FINISHED,
			},
			FAIL: Transition{
				CheckEvent: h.CheckError,
			},
			DELETE_IKE_SA: Transition{
				Dest: STATE_FINISHED,
			},
			TIMEOUT: Transition{
				Action: h.SendAuth,
			},
		},
		STATE_AUTH: UserTransitions{
			ENTRY_EVENT: Transition{
				CheckEvent: h.CheckSa,
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
