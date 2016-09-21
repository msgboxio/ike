package state

func CommonTransitions(h FsmHandler) map[State]UserTransitions {
	return map[State]UserTransitions{
		STATE_MATURE: UserTransitions{
			MSG_DELETE_IKE_SA: Transition{
				Dest:   STATE_FINISHED,
				Action: h.RemoveSa,
			},
			DELETE_IKE_SA: Transition{
				Dest:   STATE_FINISHED,
				Action: h.RemoveSa,
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

/*
map[Event][]Transition {
	return map[Event][]Transition{
		FAIL: []Transition{
			Transition{
				Source: STATE_IDLE,
				Dest:   STATE_FINISHED,
			},
			Transition{
				Source: STATE_INIT,
				Dest:   STATE_FINISHED,
			},
			Transition{
				Source: STATE_AUTH,
				Dest:   STATE_FINISHED,
			},
			Transition{
				Source: STATE_MATURE,
				Dest:   STATE_FINISHED,
				Action: h.RemoveSa,
			},
		},
		FINISHED: []Transition{
			Transition{
				Action: h.Finished,
			},
		},
	}
}
*/
