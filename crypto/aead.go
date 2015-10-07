package crypto

/*

AES-GCM :
cipher - AES block cipher in Counter Mode (AES-CTR).
MAC-  it uses a universal hash called GHASH, encrypted with AES-CTR.

AES-CCM :

sk payload ->
                        1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   ! Next Payload  !C!  RESERVED   !         Payload Length        !
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   !                     Initialization Vector                     !
   !                              8B                               !
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   ~                        Ciphertext (C)                         ~
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

P (plaintext) ->
                           1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   ~                 IKE Payloads to be Encrypted                  ~
   +               +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   !               !             Padding (0-255 octets)            !
   +-+-+-+-+-+-+-+-+                               +-+-+-+-+-+-+-+-+
   !                                               !  Pad Length   !
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

A (additional data) ->
                        1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   ~                         IKEv2 Header                          ~
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   ~                   Unencrypted IKE Payloads                    ~
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   ! Next Payload  !C!  RESERVED   !         Payload Length        !
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

K - key; 128, 192 or 256 bit; fn(ks_ex)
N - 12B (11 for CCM), Salt(not in payload) + IV
IV - 8B
ICV(T, auth tag) - integ check value; 16 B, MAY support 8, 12 B; fn(A,C)

len(C) == len(P) + len(T)
C,T <= fn(K, N, P, A)

ICV 12 is not recommended
K 192 bits is not recommended

length of SK_ai and SK_ar is 0
SK_ei and SK_er include salt bytes
if keylen is 128, then 20 bytes (16B + 4B salt)
*/
