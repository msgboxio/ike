package ike

type IkeError uint16

const (
	UNSUPPORTED_CRITICAL_PAYLOAD IkeError = 1
	INVALID_IKE_SPI              IkeError = 4
	INVALID_MAJOR_VERSION        IkeError = 5
	INVALID_SYNTAX               IkeError = 7
	INVALID_MESSAGE_ID           IkeError = 9
	INVALID_SPI                  IkeError = 11
	NO_PROPOSAL_CHOSEN           IkeError = 14
	INVALID_KE_PAYLOAD           IkeError = 17
	AUTHENTICATION_FAILED        IkeError = 24
	SINGLE_PAIR_REQUIRED         IkeError = 34
	NO_ADDITIONAL_SAS            IkeError = 35
	INTERNAL_ADDRESS_FAILURE     IkeError = 36
	FAILED_CP_REQUIRED           IkeError = 37
	TS_UNACCEPTABLE              IkeError = 38
	INVALID_SELECTORS            IkeError = 39
	TEMPORARY_FAILURE            IkeError = 43
	CHILD_SA_NOT_FOUND           IkeError = 44
)

func (e IkeError) Error() string { return "" }
