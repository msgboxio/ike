package state

import (
	"msgbox.io/context"
	"msgbox.io/log"
)

type IkeEventId int

const (
	ACQUIRE IkeEventId = iota + 1
	CONNECT
	REAUTH

	// notifications
	N_COOKIE
	N_INVALID_KE
	N_NO_PROPOSAL_CHOSEN

	// responses
	IKE_SA_INIT_RESPONSE
	IKE_AUTH_RESPONSE
	DELETE_IKE_SA_RESPONSE

	// errors
	INVALID_KE

	// common messages
	IKE_REKEY
	IKE_REKEY_RESPONSE
	IKE_DPD
	IKE_CRL_UPDATE
	IKE_REAUTH
	IKE_TERMINATE
	IKE_LEASE_RENEW

	// timeouts
	IKE_TIMEOUT

	StateEntry
	StateExit
)

type IkeEvent struct {
	Id      IkeEventId
	Message interface{}
}

type IkeSaState int

const (
	SMI_INIT IkeSaState = iota + 1
	SMI_AUTH
	SMI_AUTH_WAIT
	SMI_AUTH_PEER
	SMI_EAP
	SMI_INSTALLCSA_DL
	SMI_INSTALLCSA

	SMR_INIT
	SMR_AUTH
	SMR_AUTH_FINALIZE
	SMR_AUTH_RESPONSE_ID
	SMR_AUTH_RESPONSE
	SMR_EAP_INITATOR_REQUEST
	SMR_EAP_AAA_REQUEST
	SMR_AUTH_DL_PEER
	SMR_CFG_WAIT

	SM_MATURE
	SM_REKEY
	SM_CRL_UPDATE
	SM_REAUTH

	SM_TERMINATE
	SM_DYING
	SM_DEAD

	// child sa states
	SA_INIT
	SA_CREATE
	SA_CREATE_WAIT
	SA_MATURE
	SA_REKEY
	SA_REKEY_WAIT
	SA_REMOVE
	SA_DEAD
)

type FsmHandler interface {
	SendIkeSaInit()
	SendIkeAuth()
	HandleSaInitResponse(interface{}) error
	HandleSaAuthResponse(interface{}) error
	HandleSaRekey(interface{}) error
	DownloadCrl()
	InstallChildSa()
}

type StateFunc func(*Fsm, IkeEvent) error

type Fsm struct {
	FsmHandler
	StateFunc
	context.Context

	events chan IkeEvent

	// mandatory attributes
	State IkeSaState
}

func MakeFsm(h FsmHandler, parent context.Context) (s *Fsm) {
	s = &Fsm{
		FsmHandler: h,
		StateFunc:  SmiInit,
		Context:    parent,
		events:     make(chan IkeEvent, 10),
	}
	// go to SmiInit state
	s.StateFunc(s, IkeEvent{Id: StateEntry})
	go s.run()
	return
}

func (s *Fsm) PostEvent(evt IkeEvent) {
	select {
	case <-s.Done(): // will return immediately if closed
		break
	default:
		log.V(2).Infof("Post: Event %s, in State %s", evt.Id, s.State)
		s.events <- evt
	}
}

func (s *Fsm) runEvent(evt IkeEvent) {
	select {
	case <-s.Done(): // will return immediately if closed
		break
	default:
		log.V(2).Infof("Run: Event %s, in State %s", evt.Id, s.State)
		if err := s.StateFunc(s, evt); err != nil {

		}
	}
}

func (s *Fsm) run() {
Done:
	for {
		select {
		case <-s.Done():
			break Done
		case ev := <-s.events:
			s.runEvent(ev)
		}
	}

	close(s.events)

	return
}

func (s *Fsm) stateChange(fn StateFunc) {
	prev := s.State
	// execute exit event synchronously
	s.StateFunc(s, IkeEvent{Id: StateExit})
	// change state
	s.StateFunc = fn
	// execute new state entry event
	s.StateFunc(s, IkeEvent{Id: StateEntry})
	log.V(2).Infof("Change: Previous %s, Next %s", prev, s.State)
}

// initial state:
func SmiInit(s *Fsm, evt IkeEvent) (err error) {
	switch evt.Id {
	case StateEntry:
		s.State = SMI_INIT
	case ACQUIRE, CONNECT, REAUTH:
		// init cipher suite from config
		// create tkm
		// if nat-t is enabled, calculate hash of ips
		// crate IKE_SA_INIT and send
		s.SendIkeSaInit()
		// change to SMI_AUTH
		s.stateChange(SmiAuth)
	case StateExit:
	}
	return
}

func SmiAuth(s *Fsm, evt IkeEvent) (err error) {
	switch evt.Id {
	case StateEntry:
		s.State = SMI_AUTH
	case N_INVALID_KE, N_COOKIE:
		// recerate IKE_SA_INIT and send
	case IKE_SA_INIT_RESPONSE:
		if err = s.HandleSaInitResponse(evt.Message); err != nil {
			s.stateChange(SmDead)
		}
		s.stateChange(SmiAuthWait)
	case N_NO_PROPOSAL_CHOSEN:
		s.stateChange(SmDead)
	case IKE_TIMEOUT:
		s.stateChange(SmDead)
	case INVALID_KE:
		s.stateChange(SmTerminate)
	case StateExit:
	}
	return
}

func SmiAuthWait(s *Fsm, evt IkeEvent) (err error) {
	switch evt.Id {
	case StateEntry:
		s.State = SMI_AUTH_WAIT
		s.SendIkeAuth()
	case IKE_AUTH_RESPONSE:
		if err = s.HandleSaAuthResponse(evt.Message); err != nil {
			s.stateChange(SmDead)
		}
		s.stateChange(SmMature)
	}
	return
}

func SmMature(s *Fsm, evt IkeEvent) (err error) {
	switch evt.Id {
	case StateEntry:
		s.State = SM_MATURE
		s.InstallChildSa()
	case IKE_REKEY:
		if err = s.HandleSaRekey(evt.Message); err != nil {
			s.stateChange(SmDead)
		}
		s.stateChange(SmRekey)
	}
	return
}

func SmRekey(s *Fsm, evt IkeEvent) (err error) {
	switch evt.Id {
	case StateEntry:
		s.State = SM_REKEY
	case IKE_REKEY_RESPONSE:
	}
	return
}

func SmDead(s *Fsm, evt IkeEvent) (err error) {
	switch evt.Id {
	case StateEntry:
		s.State = SM_DEAD
	}
	return
}

func SmTerminate(s *Fsm, evt IkeEvent) (err error) {
	switch evt.Id {
	case StateEntry:
		s.State = SM_TERMINATE
	case IKE_TIMEOUT:
		s.State = SM_DEAD
	}
	return
}

func SmDying(s *Fsm, evt IkeEvent) (err error) {
	switch evt.Id {
	case StateEntry:
		s.State = SM_DYING
	}
	return
}
