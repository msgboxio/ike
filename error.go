package ike

type IkeError uint16

const (
	ERR_UNSUPPORTED_CRITICAL_PAYLOAD IkeError = 1
	ERR_INVALID_IKE_SPI              IkeError = 4
	ERR_INVALID_MAJOR_VERSION        IkeError = 5
	ERR_INVALID_SYNTAX               IkeError = 7
	ERR_INVALID_MESSAGE_ID           IkeError = 9
	ERR_INVALID_SPI                  IkeError = 11
	ERR_NO_PROPOSAL_CHOSEN           IkeError = 14
	ERR_INVALID_KE_PAYLOAD           IkeError = 17
	ERR_AUTHENTICATION_FAILED        IkeError = 24
	ERR_SINGLE_PAIR_REQUIRED         IkeError = 34
	ERR_NO_ADDITIONAL_SAS            IkeError = 35
	ERR_INTERNAL_ADDRESS_FAILURE     IkeError = 36
	ERR_FAILED_CP_REQUIRED           IkeError = 37
	ERR_TS_UNACCEPTABLE              IkeError = 38
	ERR_INVALID_SELECTORS            IkeError = 39
	ERR_TEMPORARY_FAILURE            IkeError = 43
	ERR_CHILD_SA_NOT_FOUND           IkeError = 44
)

func (e IkeError) Error() string { return "" }
