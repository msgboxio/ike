# initiator
docker run -it --rm --privileged -v /ike/server:/server -v /ike/test/cert:/cert min /server -local ":500" -remote "172.17.0.2:500" -ca /cert/cacert.pem -key /cert/peerkey.der -cert /cert/peercert.der -tunnel

go run cmd/server.go -ca test/cert/cacert.pem -key test/cert/peerkey.der -cert test/cert/peercert.der -peerid "172.17.0.1" -local ":5000" -remote ":4500"

sudo ./server.elf -remote=172.28.128.1:500 -id ak@msgbox.io -pass foo -ca test/cert/cacert.pem -peerid "172.17.0.1"

# responder
docker run -it --rm --privileged -v /ike/server:/server -v /ike/test/cert:/cert min /server -local ":500" -v 2 -ca /cert/cacert.pem -key /cert/hostkey.der -cert /cert/hostcert.der -tunnel

go run cmd/server.go -ca test/cert/cacert.pem -key test/cert/hostkey.der -cert test/cert/hostcert.der -peerid "172.17.0.2" -local ":4500"

sudo ./server -local=172.28.128.1:500 -key test/cert/hostkey.der -cert test/cert/hostcert.der -peerid ak@msgbox.io -peerpass foo

# tests
./ike.test -test.v -v 4 -logtostderr -test.run="^TestCommonVersions$"

# cert
## generate host key
ipsec pki --gen --type rsa --size 2048 --outform der > cert/hostkey.der
## cert request & sign key
ipsec pki --pub --in cert/hostkey.der --type rsa | ipsec pki --issue --lifetime 730 --cacert cert/cacert.pem --cakey cert/cakey.pem --dn "C=NL, O=Example Company, CN=172.17.0.1" --flag serverAuth --flag ikeIntermediate --outform der > cert/hostcert.der

# multihost 
docker network create --subnet 172.30.1.0/24 --gateway=172.30.1.1 \
        --opt com.docker.network.bridge.name=net2 \
        --opt com.docker.network.bridge.enable_ip_masquerade=false \
		net2

docker run -it --rm --privileged --net=net2 alpine sh

docker network create --subnet 172.30.2.0/24 --gateway=172.30.2.1 \
        --opt com.docker.network.bridge.name=net2 \
        --opt com.docker.network.bridge.enable_ip_masquerade=false \
		net2

docker run -it --rm --privileged --net=net2 alpine sh

> client
sudo ./server.elf -remote=172.28.128.4:4500 -localnet=172.30.1.0/24 \
-remotenet=172.30.2.0/24

> server
sudo ./server.elf -remotenet=172.30.1.0/24 -localnet=172.30.2.0/24

# manual settings for multihost tunnel
./doipsec.sh '172.28.128.3|172.30.1.0/24|172.30.1.1|enp0s8' \
    '172.28.128.4|172.30.2.0/24|172.30.2.1|enp0s8'

route is only needed for host originated packets

# bugs

# TODO:
> nat traversal
> allow external authentication
> allow external control - adding / stopping initiators & responders
> make sure it works with tcp
> dont allow selector & crypto change on rekey
> send & accept all available suites
> errors need to be looked at more closely

# tests needed
> cookie handling
> requestid handling
> CheckProposals
> NO_PROPOSAL_CHOSEN - INIT & AUTH
> responder: peer pass is wrong, send AUTH response
> responder: our pass is wrong, peer sends INFO
> disable secure signature