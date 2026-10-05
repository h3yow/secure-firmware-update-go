package device

// This file exposes the mutating/reading operations as methods on Tx (the
// cross-process-safe entry points) and keeps the historical Store methods as
// thin "begin / run / commit" wrappers for standalone callers and tests.

// --- Tx methods: run while both locks are held ---

// Snapshot returns an external view of the current state.
func (tx *Tx) Snapshot() State { return tx.s.viewLocked() }

// Store returns the underlying store (for read-only helpers only).
func (tx *Tx) Store() *Store { return tx.s }

// Stage writes a new payload into the inactive slot.
func (tx *Tx) Stage(meta SlotState, payload []byte, opts ...Option) error {
	return tx.s.stageLocked(meta, payload, opts...)
}

// Activate flips the boot pointer to the staged slot.
func (tx *Tx) Activate(opts ...Option) error {
	return tx.s.activateLocked(opts...)
}

// Confirm marks the active trial image as known-good.
func (tx *Tx) Confirm(opts ...Option) error {
	return tx.s.confirmLocked(opts...)
}

// Rollback discards a pending trial and returns to its known-good version.
func (tx *Tx) Rollback(opts ...Option) error {
	return tx.s.rollbackLocked(opts...)
}

// Revert returns to the retained previous known-good version post-confirm.
func (tx *Tx) Revert(opts ...Option) error {
	return tx.s.revertLocked(opts...)
}

// RecoverOnBoot applies trial-boot / watchdog policy.
func (tx *Tx) RecoverOnBoot(opts ...Option) (bool, error) {
	return tx.s.recoverOnBootLocked(opts...)
}

// ReadPayload returns the payload bytes of the active slot.
func (tx *Tx) ReadPayload() ([]byte, error) {
	return tx.s.readPayloadLocked()
}

// --- Legacy Store wrappers: each opens its own exclusive transaction ---

// Stage writes the payload into the inactive slot.
func (s *Store) Stage(meta SlotState, payload []byte, opts ...Option) error {
	tx, err := s.Begin()
	if err != nil {
		return err
	}
	if err := tx.Stage(meta, payload, opts...); err != nil {
		_ = tx.Abort()
		return err
	}
	return tx.Commit()
}

// Activate flips the boot pointer to the staged slot.
func (s *Store) Activate(opts ...Option) error {
	tx, err := s.Begin()
	if err != nil {
		return err
	}
	if err := tx.Activate(opts...); err != nil {
		_ = tx.Abort()
		return err
	}
	return tx.Commit()
}

// Confirm marks the active trial image as good.
func (s *Store) Confirm(opts ...Option) error {
	tx, err := s.Begin()
	if err != nil {
		return err
	}
	if err := tx.Confirm(opts...); err != nil {
		_ = tx.Abort()
		return err
	}
	return tx.Commit()
}

// Rollback restores the previous known-good slot.
func (s *Store) Rollback(opts ...Option) error {
	tx, err := s.Begin()
	if err != nil {
		return err
	}
	if err := tx.Rollback(opts...); err != nil {
		_ = tx.Abort()
		return err
	}
	return tx.Commit()
}

// Revert flips back to the retained previous known-good version.
func (s *Store) Revert(opts ...Option) error {
	tx, err := s.Begin()
	if err != nil {
		return err
	}
	if err := tx.Revert(opts...); err != nil {
		_ = tx.Abort()
		return err
	}
	return tx.Commit()
}

// RecoverOnBoot performs boot-time trial/watchdog recovery.
func (s *Store) RecoverOnBoot(opts ...Option) (bool, error) {
	tx, err := s.Begin()
	if err != nil {
		return false, err
	}
	rolledBack, err := tx.RecoverOnBoot(opts...)
	if err != nil {
		_ = tx.Abort()
		return false, err
	}
	if err := tx.Commit(); err != nil {
		return false, err
	}
	return rolledBack, nil
}

// ReadPayload returns the payload bytes of the currently active slot.
func (s *Store) ReadPayload() ([]byte, error) {
	tx, err := s.Begin()
	if err != nil {
		return nil, err
	}
	b, err := tx.ReadPayload()
	if err != nil {
		_ = tx.Abort()
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return b, nil
}
