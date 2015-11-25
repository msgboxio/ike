package state

func CommonTransitions(h FsmHandler) map[Event][]Transition {
	return map[Event][]Transition{
		FAIL: []Transition{
			Transition{
				source: STATE_IDLE,
				dest:   STATE_FINISHED,
			},
			Transition{
				source: STATE_INIT,
				dest:   STATE_FINISHED,
			},
			Transition{
				source: STATE_AUTH,
				dest:   STATE_FINISHED,
			},
			Transition{
				source: STATE_MATURE,
				dest:   STATE_FINISHED,
				action: h.RemoveSa,
			},
		},

		DELETE_IKE_SA: []Transition{
			Transition{
				source: STATE_MATURE,
				dest:   STATE_FINISHED,
				action: h.RemoveSa,
			},
		},

		FINISHED: []Transition{
			Transition{
				action: h.Finished,
			},
		},
	}
}
