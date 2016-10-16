package state

type State uint32

const (
	STATE_IDLE State = iota
	STATE_START

	STATE_INIT
	STATE_AUTH
	STATE_MATURE

	STATE_CLOSING
	STATE_FINISHED
)

type Event uint32

const (
	SUCCESS Event = iota
	FAIL          // unrecoverable failure

	MSG_INIT
	MSG_AUTH
	MSG_CHILD_SA
	MSG_DELETE_IKE_SA
	MSG_DELETE_ESP_SA
	MSG_EMPTY_REQUEST
	MSG_EMPTY_RESPONSE

	SMI_START
	REKEY_START

	TIMEOUT
	INIT_FAIL
	AUTH_FAIL

	DELETE_IKE_SA

	FINISHED // internal event
	ENTRY_EVENT
)

type StateEvent struct {
	Event
	Message interface{}
	Error   error
}

type FsmHandler interface {
	// actions
	SendInit(*StateEvent) *StateEvent
	SendAuth(*StateEvent) *StateEvent
	InstallSa(*StateEvent) *StateEvent
	RemoveSa(*StateEvent) *StateEvent
	Finished(*StateEvent) *StateEvent

	// checks
	HandleIkeSaInit(*StateEvent) *StateEvent
	HandleIkeAuth(*StateEvent) *StateEvent
	CheckSa(*StateEvent) *StateEvent
	HandleCreateChildSa(*StateEvent) *StateEvent
	HandleClose(*StateEvent) *StateEvent
	CheckError(*StateEvent) *StateEvent
}
