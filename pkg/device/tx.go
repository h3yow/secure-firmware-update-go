package device

// Tx is an exclusive device transaction: the caller holds both the
// in-process mutex and the cross-process file lock, so no other goroutine or
// process can observe or mutate the device while the transaction is open.
//
// State is always reloaded from disk when a transaction begins, so a freshly
// opened transaction sees every change committed by previous processes even
// when the Store instance itself is long-lived.
//
// Callers must end the transaction with Commit (or Abort; both release the
// locks). The zero value is not usable; obtain one via Store.Begin.
type Tx struct {
	s       *Store
	closed  bool
	aborted bool
}

// Begin starts an exclusive read-write transaction. It blocks until every
// other in-process goroutine and every other process holding the store lock
// has released it.
func (s *Store) Begin() (*Tx, error) {
	s.mu.Lock()
	if s.lock == nil {
		lk, err := openDirLock(s.dir)
		if err != nil {
			s.mu.Unlock()
			return nil, err
		}
		s.lock = lk
	}
	if err := s.lock.acquire(); err != nil {
		s.mu.Unlock()
		return nil, err
	}
	if err := s.reloadLocked(); err != nil {
		_ = s.lock.release()
		s.mu.Unlock()
		return nil, err
	}
	if err := s.reconcileLocked(); err != nil {
		_ = s.lock.release()
		s.mu.Unlock()
		return nil, err
	}
	return &Tx{s: s}, nil
}

// Commit ends the transaction and releases all locks.
func (tx *Tx) Commit() error { return tx.finish() }

// Abort ends the transaction without signalling anything extra; in-memory
// caches are discarded on the next Begin and only persisted state survives.
func (tx *Tx) Abort() error {
	tx.aborted = true
	return tx.finish()
}

func (tx *Tx) finish() error {
	if tx == nil || tx.closed {
		return nil
	}
	tx.closed = true
	s := tx.s
	var relErr error
	if s.lock != nil {
		relErr = s.lock.release()
	}
	s.mu.Unlock()
	return relErr
}

// reloadLocked re-reads state.json from disk so the transaction operates on
// the latest durable state (possibly written by another process).
func (s *Store) reloadLocked() error {
	b, err := readStateFile(s.dir)
	if err != nil {
		return err
	}
	var in internalState
	if err := unmarshalState(b, &in); err != nil {
		return err
	}
	if in.Schema != 1 {
		return errUnsupportedSchema(in.Schema)
	}
	if in.ActiveSlot != slotA && in.ActiveSlot != slotB {
		return errBadActiveSlot(in.ActiveSlot)
	}
	if in.Slots == nil {
		in.Slots = map[string]SlotState{}
	}
	s.inner = in
	return nil
}
