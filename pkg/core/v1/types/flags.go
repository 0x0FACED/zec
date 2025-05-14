package types

// File header flags (refactor)
const (
	FlagUndefined  = 0               // undefined flag set in the start of writing
	FlagCompleted  = 1 << (iota - 1) // 1
	FlagEncrypted                    // 2
	FlagCompressed                   // 4
	FlagDeleted                      // 8
)

const (
	AlgoChacha20 = 1 << iota
	AlgoAESGCM
	AlgoAESCCM
)

var FlagNames = map[uint8]string{
	FlagUndefined:  "U",
	FlagCompleted:  "C",
	FlagEncrypted:  "E",
	FlagCompressed: "X",
	FlagDeleted:    "D",
}
