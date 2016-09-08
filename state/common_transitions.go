package state

func CommonTransitions(h FsmHandler) map[Event][]Transition {
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

		DELETE_IKE_SA: []Transition{
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
