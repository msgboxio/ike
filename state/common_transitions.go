package state

func CommonTransitions(h FsmHandler) map[State]UserTransitions {
	return map[State]UserTransitions{
		STATE_MATURE: UserTransitions{
			MSG_DELETE_IKE_SA: Transition{
				CheckEvent: h.HandleClose,
				Dest:       STATE_FINISHED,
			},
			DELETE_IKE_SA: Transition{
				Dest: STATE_CLOSING,
			},
			MSG_CHILD_SA: Transition{
				CheckEvent: h.HandleCreateChildSa,
			},
			INIT_FAIL: Transition{
				CheckEvent: h.CheckError,
			},
			AUTH_FAIL: Transition{
				CheckEvent: h.CheckError,
			},
			FAIL: Transition{
				Dest:   STATE_FINISHED,
				Action: h.RemoveSa,
			},
		},
		STATE_CLOSING: UserTransitions{
			MSG_EMPTY_RESPONSE: Transition{
				Action: h.RemoveSa,
				Dest:   STATE_FINISHED,
			},
		},
		STATE_FINISHED: UserTransitions{
			ENTRY_EVENT: Transition{
				Action: h.Finished,
			},
			FINISHED: Transition{
				Action: h.Finished,
			},
		},
	}
}
