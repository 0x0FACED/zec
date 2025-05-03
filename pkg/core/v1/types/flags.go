package types

// File header flags (refactor)
const (
	FlagUndefined = 0 // undefined flag set in the start of writing
	FlagCompleted = 1 << (iota - 1)
	FlagEncrypted
	FlagCompressed
	FlagDeleted
)

const (
	AlgoChacha20 = 1 << iota
	AlgoAESGCM
	AlgoAESCCM
)
