package ike

import "time"

const REPLY_WAIT_TIMEOUT = 5 * time.Second

var ReplyTimedoutError error = replyTimeout{}

type replyTimeout struct{}

func (r replyTimeout) Error() string {
	return "Timed Out"
}

func packetOrTimeOut(incoming <-chan *Message) (*Message, error) {
	select {
	case msg, ok := <-incoming:
		if ok {
			return msg, nil
		}
		return nil, sessionClosedError
	case <-time.After(Jitter(REPLY_WAIT_TIMEOUT, 0.2)):
		return nil, ReplyTimedoutError
	}
}
