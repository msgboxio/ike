package ike

import "sync"

type Sessions interface {
	Add(spi uint64, session *Session)
	Remove(spi uint64)
	Get(spi uint64) (*Session, bool)
	ForEach(action func(*Session))
}

func NewSessions() Sessions {
	return &sessions{
		_sessions: make(map[uint64]*Session),
	}
}

type sessions struct {
	_sessions map[uint64]*Session
	mtx       sync.Mutex
}

func (s *sessions) Add(spi uint64, sess *Session) {
	s.mtx.Lock()
	defer s.mtx.Unlock()
	s._sessions[spi] = sess
}

func (s *sessions) Remove(spi uint64) {
	s.mtx.Lock()
	defer s.mtx.Unlock()
	delete(s._sessions, spi)
}

func (s *sessions) Get(spi uint64) (*Session, bool) {
	s.mtx.Lock()
	defer s.mtx.Unlock()
	session, found := s._sessions[spi]
	return session, found
}

func (s *sessions) ForEach(action func(*Session)) {
	s.mtx.Lock()
	var temp []*Session
	for _, session := range s._sessions {
		temp = append(temp, session)
	}
	s.mtx.Unlock()
	for _, session := range temp {
		action(session)
	}
}
