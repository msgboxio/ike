package ike

// ike-seperation.pdf

// 2.1.2 IKE_SA_INIT
// tkm creates KEi, Ni

// get SKEYSEED
// derive SK_e (encryption) and SK_a (authentication)

// 2.1.3 IKE_AUTH
// tkm creates SK, AUTH

// 2.1.4 CREATE_CHILD_SA
// a->b HDR, SK {SA, Ni, [KEi], TSi, TSr}
// b->a HDR, SK {SA, Nr, [KEr], TSi, TSr}
// tkm creates SK, Ni, [KEi]

// 4.1.2 creation of ike sa

// The client gets the nonce & dh public value
func nc_create(nc_id []byte) (ni []byte) { return }

func dh_create(dh_id, hd_group []byte) (kei []byte) { return }

// upon receipt of peers resp, a dh shared secret can be calculated
// client creates & stores the dh key
func dh_generate_key(hd_id, ker []byte) {}

// create ike sa
func isa_create(isa_id, ae_id, ia_id, dh_id, nc_id, nr, init, spi_loc, spi_rem []byte) (sk_ai, sk_ar, sk_ei, sk_er []byte) {
	return
}

// request signed data from tkm
func isa_sign(isa_id, lc_id, init_message []byte) (AUTH_loc []byte) { return }

// cert validation
// start vaildating cert chain
func cc_set_user_certficate(cc_id, ri_id, au_tha_id, CERT []byte) {}

// add remianing certs in chain
func cc_add_certificate(cc_id, autha_id, CERT []byte) {}

// validate
func cc_check_ca(cc_id, ca_id []byte) {}

// after cert validtaion, authenticate peer
func isa_auth(isa_id, cc_id, init_message, AUTH_rem []byte) {}

// create first child sa
func esa_create_first(esa_id, isa_id, sp_id, ea_id, esp_spi_loc, esp_spi_rem []byte) {}
