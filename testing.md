# initiator
docker run -it --rm --privileged -v /ike/server:/server -v /ike/test/cert:/cert min /server -local ":500" -remote "172.17.0.2:500" -ca /cert/cacert.pem -key /cert/peerkey.der -cert /cert/peercert.der -tunnel

go run cmd/server.go -ca test/cert/cacert.pem -key test/cert/peerkey.der -cert test/cert/peercert.der -peerid "172.17.0.1" -local ":5000" -remote ":4500"

# responder
docker run -it --rm --privileged -v /ike/server:/server -v /ike/test/cert:/cert min /server -local ":500" -v 2 -ca /cert/cacert.pem -key /cert/hostkey.der -cert /cert/hostcert.der -tunnel

go run cmd/server.go -ca test/cert/cacert.pem -key test/cert/hostkey.der -cert test/cert/hostcert.der -peerid "172.17.0.2" -local ":4500"

# tests
./ike.test -test.v -v 4 -logtostderr -test.run="^TestCommonVersions$"

# cert
## generate host key
ipsec pki --gen --type rsa --size 2048 --outform der > cert/hostkey.der
## cert request & sign key
ipsec pki --pub --in cert/hostkey.der --type rsa | ipsec pki --issue --lifetime 730 --cacert cert/cacert.pem --cakey cert/cakey.pem --dn "C=NL, O=Example Company, CN=172.17.0.1" --flag serverAuth --flag ikeIntermediate --outform der > cert/hostcert.der
