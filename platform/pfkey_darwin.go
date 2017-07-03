package platform

import (
	"context"
	"net"
	"os"
	"os/exec"
	"syscall"
	"unsafe"

	"fmt"

	"runtime"

	"github.com/davecgh/go-spew/spew"
	"github.com/go-kit/kit/log"
	"github.com/go-kit/kit/log/level"
	"github.com/msgboxio/ike/protocol"
	"github.com/pkg/errors"
)

const (
	syscall_AF_KEY   = 29
	syscall_SOL_IP   = 0
	syscall_SOL_IPV6 = 41

	PF_KEY_V2 = 2

	SADB_RESERVED  = 0
	SADB_GETSPI    = 1
	SADB_UPDATE    = 2
	SADB_ADD       = 3
	SADB_DELETE    = 4
	SADB_GET       = 5
	SADB_ACQUIRE   = 6
	SADB_REGISTER  = 7
	SADB_EXPIRE    = 8
	SADB_FLUSH     = 9
	SADB_DUMP      = 10
	SADB_X_PROMISC = 11
	SADB_X_PCHANGE = 12

	SADB_X_SPDUPDATE  = 13
	SADB_X_SPDADD     = 14
	SADB_X_SPDDELETE  = 15
	SADB_X_SPDGET     = 16
	SADB_X_SPDACQUIRE = 17
	SADB_X_SPDDUMP    = 18
	SADB_X_SPDFLUSH   = 19
	SADB_X_SPDSETIDX  = 20
	SADB_X_SPDEXPIRE  = 21
	SADB_X_SPDDELETE2 = 22
	SADB_GETSASTAT    = 23
	SADB_X_SPDENABLE  = 24
	SADB_X_SPDDISABLE = 25
	SADB_MIGRATE      = 26
	SADB_MAX          = 26

	SADB_X_SATYPE_TCPSIGNATURE = 8

	SADB_EXT_RESERVED               = 0
	SADB_EXT_SA                     = 1
	SADB_EXT_LIFETIME_CURRENT       = 2
	SADB_EXT_LIFETIME_HARD          = 3
	SADB_EXT_LIFETIME_SOFT          = 4
	SADB_EXT_ADDRESS_SRC            = 5
	SADB_EXT_ADDRESS_DST            = 6
	SADB_EXT_ADDRESS_PROXY          = 7
	SADB_EXT_KEY_AUTH               = 8
	SADB_EXT_KEY_ENCRYPT            = 9
	SADB_EXT_IDENTITY_SRC           = 10
	SADB_EXT_IDENTITY_DST           = 11
	SADB_EXT_SENSITIVITY            = 12
	SADB_EXT_PROPOSAL               = 13
	SADB_EXT_SUPPORTED_AUTH         = 14
	SADB_EXT_SUPPORTED_ENCRYPT      = 15
	SADB_EXT_SPIRANGE               = 16
	SADB_X_EXT_KMPRIVATE            = 17
	SADB_X_EXT_POLICY               = 18
	SADB_X_EXT_SA2                  = 19
	SADB_EXT_SESSION_ID             = 20
	SADB_EXT_SASTAT                 = 21
	SADB_X_EXT_IPSECIF              = 22
	SADB_X_EXT_ADDR_RANGE_SRC_START = 23
	SADB_X_EXT_ADDR_RANGE_SRC_END   = 24
	SADB_X_EXT_ADDR_RANGE_DST_START = 25
	SADB_X_EXT_ADDR_RANGE_DST_END   = 26
	SADB_EXT_MIGRATE_ADDRESS_SRC    = 27
	SADB_EXT_MIGRATE_ADDRESS_DST    = 28
	SADB_X_EXT_MIGRATE_IPSECIF      = 29
	SADB_EXT_MAX                    = 29

	SADB_SATYPE_UNSPEC   = 0
	SADB_SATYPE_AH       = 2
	SADB_SATYPE_ESP      = 3
	SADB_SATYPE_RSVP     = 5
	SADB_SATYPE_OSPFV2   = 6
	SADB_SATYPE_RIPV2    = 7
	SADB_SATYPE_MIP      = 8
	SADB_X_SATYPE_IPCOMP = 9
	SADB_X_SATYPE_POLICY = 10
	SADB_SATYPE_MAX      = 11

	SADB_SASTATE_LARVAL = 0
	SADB_SASTATE_MATURE = 1
	SADB_SASTATE_DYING  = 2
	SADB_SASTATE_DEAD   = 3
	SADB_SASTATE_MAX    = 3

	SADB_SAFLAGS_PFS = 1

	/* RFC2367 numbers - meets RFC2407 */
	SADB_AALG_NONE     = 0
	SADB_AALG_MD5HMAC  = 1 /*2*/
	SADB_AALG_SHA1HMAC = 2 /*3*/
	SADB_AALG_MAX      = 8
	/* private allocations - based on RFC2407/IANA assignment */
	SADB_X_AALG_SHA2_256 = 6 /*5*/
	SADB_X_AALG_SHA2_384 = 7 /*6*/
	SADB_X_AALG_SHA2_512 = 8 /*7*/
	/* private allocations should use 249-255 (RFC2407) */
	SADB_X_AALG_MD5  = 3 /*249*/ /* Keyed MD5 */
	SADB_X_AALG_SHA  = 4 /*250*/ /* Keyed SHA */
	SADB_X_AALG_NULL = 5 /*251*/ /* null authentication */

	/* RFC2367 numbers - meets RFC2407 */
	SADB_EALG_NONE    = 0
	SADB_EALG_DESCBC  = 1 /*2*/
	SADB_EALG_3DESCBC = 2 /*3*/
	SADB_EALG_NULL    = 3 /*11*/
	SADB_EALG_MAX     = 12
	/* private allocations - based on RFC2407/IANA assignment */
	SADB_X_EALG_CAST128CBC  = 5 /*6*/
	SADB_X_EALG_BLOWFISHCBC = 4 /*7*/
	SADB_X_EALG_RIJNDAELCBC = 12
	SADB_X_EALG_AESCBC      = 12
	SADB_X_EALG_AES         = 12
	SADB_X_EALG_AES_GCM     = 13
	/* private allocations should use 249-255 (RFC2407) */

	IP_IPSEC_POLICY   = 21
	IPV6_IPSEC_POLICY = 28

	/*
	 * Direction of security policy.
	 * NOTE: Since INVALID is used just as flag.
	 * The other are used for loop counter too.
	 */
	IPSEC_DIR_ANY      = 0
	IPSEC_DIR_INBOUND  = 1
	IPSEC_DIR_OUTBOUND = 2
	IPSEC_DIR_MAX      = 3
	IPSEC_DIR_INVALID  = 4

	/* Policy level */
	/*
	 * IPSEC, ENTRUST and BYPASS are allowed for setsockopt() in PCB,
	 * DISCARD, IPSEC and NONE are allowed for setkey() in SPD.
	 * DISCARD and NONE are allowed for system default.
	 */
	IPSEC_POLICY_DISCARD  = 0 /* discarding packet */
	IPSEC_POLICY_NONE     = 1 /* through IPsec engine */
	IPSEC_POLICY_IPSEC    = 2 /* do IPsec */
	IPSEC_POLICY_ENTRUST  = 3 /* consulting SPD if present. */
	IPSEC_POLICY_BYPASS   = 4 /* only for privileged socket. */
	IPSEC_POLICY_GENERATE = 5 /* same as discard - IKE daemon can override with generated policy */

	/* Security protocol level */
	IPSEC_LEVEL_DEFAULT = 0 /* reference to system default */
	IPSEC_LEVEL_USE     = 1 /* use SA if present. */
	IPSEC_LEVEL_REQUIRE = 2 /* require SA. */
	IPSEC_LEVEL_UNIQUE  = 3 /* unique SA. */
)

/* sizeof(struct sadb_x_policy) == 16 */
type sadbPolicy struct {
	sadbPolicyLen       uint16
	sadbPolicyExttype   uint16
	sadbPolicyType      uint16 /* See policy type of ipsec.h */
	sadbPolicyDir       uint8  /* direction, see ipsec.h */
	sadbPolicyReserved  uint8
	sadbPolicyId        uint32
	sadbPolicyReserved2 uint32
}

const SADB_POLICY_SIZE = 16

func makeSaPolicies(pol *protocol.PolicyParams, forInitiator bool) (policies [][]string) {
	/*
		spdadd 10.0.0.0/16 10.1.0.0/16 any
			   -P out ipsec
		       esp/tunnel/83.56.124.167-62.149.40.78/require;
	*/
	// if initiator ? ini -> res is out
	dir := "in"
	if forInitiator {
		dir = "out"
	}
	tun := fmt.Sprintf("esp/tunnel/%s-%s/require;", pol.Ini, pol.Res)
	if pol.IsTransportMode {
		tun = fmt.Sprintf("esp/transport//require;")
	}
	initP := []string{
		pol.IniNet.String(),
		pol.ResNet.String(),
		"any",
		"-P",
		fmt.Sprintf("%s", dir),
		"ipsec",
		fmt.Sprintf("%s", tun),
	}

	// if initiator ? res -> ini is in
	dir = "out"
	if forInitiator {
		dir = "in"
	}
	tun = fmt.Sprintf("esp/tunnel/%s-%s/require;", pol.Res, pol.Ini)
	if pol.IsTransportMode {
		tun = fmt.Sprintf("esp/transport//require;")
	}
	initR := []string{
		pol.ResNet.String(),
		pol.IniNet.String(),
		"any",
		"-P",
		fmt.Sprintf("%s", dir),
		"ipsec",
		fmt.Sprintf("%s", tun),
	}
	return [][]string{
		initP,
		initR,
	}
}

func encrTransform(tr *protocol.SaTransform) (crypt string) {
	switch protocol.EncrTransformId(tr.Transform.TransformId) {
	case protocol.AEAD_AES_GCM_16:
	case protocol.AEAD_CHACHA20_POLY1305:
	case protocol.ENCR_AES_CBC:
		return "aes-cbc"
	}
	return ""
}

func authTransform(tr *protocol.SaTransform) (auth string) {
	switch protocol.AuthTransformId(tr.Transform.TransformId) {
	case protocol.AUTH_HMAC_SHA1_96:
		return "hmac-sha1"
	case protocol.AUTH_HMAC_SHA2_256_128:
		return "hmac-sha256"
	case protocol.AUTH_HMAC_SHA2_384_192:
		return "hmac-sha384"
	case protocol.AUTH_HMAC_SHA2_512_256:
		return "hmac-sha512"
	}
	return ""
}
func espTransforms(tr protocol.TransformMap) (crypt string, auth string, err error) {
	// return "aes-cbc", "hmac-sha256", nil
	for ttype, transform := range tr {
		switch ttype {
		case protocol.TRANSFORM_TYPE_ENCR:
			crypt = encrTransform(transform)
		case protocol.TRANSFORM_TYPE_INTEG:
			auth = authTransform(transform)
		case protocol.TRANSFORM_TYPE_ESN:
			if transform.Transform.TransformId != uint16(protocol.ESN_NONE) {
				err = fmt.Errorf("ESN is not supported on %s", runtime.GOOS)
			}
		}
	}
	if auth == "" || crypt == "" {
		err = errors.New("Transform is not supported")
	}
	return
}

func makeSaStates(sa *SaParams) ([][]string, error) {
	/*
	   	add 83.56.124.167 62.149.40.78 esp-udp 0x0c7042de
	          -m tunnel -r 4
	          -E aes-cbc 0x56fec3445ff820f116f8701e1abf6c37
	          -A hmac-sha1 0xb9bf971bdab9a41d5ceb2ae4641dd215101f44a8
	*/
	mode := "tunnel"
	if sa.IsTransportMode {
		mode = "transport"
	}
	encr, auth, err := espTransforms(sa.EspTransforms)
	if err != nil {
		return nil, err
	}
	// initiator
	init := []string{
		sa.Ini.String(), // src
		sa.Res.String(), // dst
		"esp", fmt.Sprintf("0x%x", sa.SpiR),
		"-m", mode,
		"-r", "4",
		"-E", encr, fmt.Sprintf("0x%x", sa.EspEi),
		"-A", auth, fmt.Sprintf("0x%x", sa.EspAi),
		";",
	}
	// responder
	resp := []string{
		sa.Res.String(),
		sa.Ini.String(),
		"esp", fmt.Sprintf("0x%x", sa.SpiI),
		"-m", mode,
		"-r", "4",
		"-E", encr, fmt.Sprintf("0x%x", sa.EspEr),
		"-A", auth, fmt.Sprintf("0x%x", sa.EspAr),
		";",
	}
	return [][]string{
		init,
		resp,
	}, nil
}

func makeSaDeleteStates(sa *SaParams) ([][]string, error) {
	/*
		delete [-46n] src dst protocol spi;
	*/
	// initiator
	init := []string{
		sa.Ini.String(), // src
		sa.Res.String(), // dst
		"esp", fmt.Sprintf("0x%x", sa.SpiR),
		";",
	}
	// responder
	resp := []string{
		sa.Res.String(),
		sa.Ini.String(),
		"esp", fmt.Sprintf("0x%x", sa.SpiI),
		";",
	}
	return [][]string{
		init,
		resp,
	}, nil
}

func call(action string, args []string) error {
	str := action
	for _, a := range args {
		str = fmt.Sprintf("%s %s", str, a)
	}
	cmd := fmt.Sprintf("echo '%s' | setkey -c", str)
	_, err := exec.Command("sh", "-c", cmd).Output()
	return err
}

func InstallPolicy(sid int32, pol *protocol.PolicyParams, log log.Logger, forInitiator bool) error {
	for _, policy := range makeSaPolicies(pol, forInitiator) {
		level.Debug(log).Log("INSTALL_POLICY", spew.Sprintf("%v", policy))
		if err := call("spdadd", policy); err != nil {
			return err
		}
	}
	return nil
}

func RemovePolicy(sid int32, pol *protocol.PolicyParams, log log.Logger, forInitiator bool) error {
	for _, policy := range makeSaPolicies(pol, forInitiator) {
		level.Debug(log).Log("REMOVE_POLICY", spew.Sprintf("%v", policy))
		if err := call("spddelete", policy); err != nil {
			return err
		}
	}
	return nil
}

func InstallChildSa(sid int32, sa *SaParams, log log.Logger) error {
	states, err := makeSaStates(sa)
	for _, sa := range states {
		level.Debug(log).Log("ADD_STATE", spew.Sprintf("%v", sa))
		if err := call("add", sa); err != nil {
			return err
		}
	}
	return err
}

func RemoveChildSa(sid int32, sa *SaParams, log log.Logger) error {
	states, err := makeSaDeleteStates(sa)
	for _, sa := range states {
		level.Debug(log).Log("REMOVE_STATE", spew.Sprintf("%v", sa))
		if err := call("delete", sa); err != nil {
			return err
		}
	}
	return err
}

func SetSocketBypass(conn net.Conn) error {
	fd, family, err := sysfd(conn)
	if err != nil {
		return errors.WithStack(err)
	}
	policy := sadbPolicy{}

	sol := syscall_SOL_IP
	ipsecPolicy := IP_IPSEC_POLICY
	if family == syscall.AF_INET6 {
		sol = syscall_SOL_IPV6
		ipsecPolicy = IPV6_IPSEC_POLICY
	}
	policy.sadbPolicyLen = uint16(SADB_POLICY_SIZE / 8)
	policy.sadbPolicyExttype = SADB_X_EXT_POLICY
	policy.sadbPolicyType = IPSEC_POLICY_BYPASS

	policy.sadbPolicyDir = IPSEC_DIR_OUTBOUND
	err = os.NewSyscallError("setsockopt", setsockopt(fd, sol, ipsecPolicy, unsafe.Pointer(&policy), SADB_POLICY_SIZE))
	if err != nil {
		return errors.WithStack(err)
	}
	policy.sadbPolicyDir = IPSEC_DIR_INBOUND
	return os.NewSyscallError("setsockopt", setsockopt(fd, sol, ipsecPolicy, unsafe.Pointer(&policy), SADB_POLICY_SIZE))
}

func ListenForEvents(context.Context, func(interface{}), log.Logger) {
}
