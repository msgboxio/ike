package ike

import (
	"log"

	"github.com/pkg/errors"
)

type msgID struct {
	id        int
	confirmed bool
}

func (m *msgID) confirm() (err error) {
	if m.confirmed {
		err = errors.New("confirming a confirmed id")
		log.Printf("%+v", err)
		return
	}
	m.id++
	m.confirmed = true
	return
}

// TODO - handle overflow
func (m *msgID) next() uint32 {
	if m.confirmed {
		m.confirmed = false
	}
	return uint32(m.id)
}

func (m *msgID) get() int {
	return m.id
}
