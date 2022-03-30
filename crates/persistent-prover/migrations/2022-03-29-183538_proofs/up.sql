CREATE TABLE proofs (
    id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,
    first_epoch_index INTEGER NOT NULL,
    first_epoch BLOB NOT NULL,
    last_epoch_index INTEGER NOT NULL,
    last_epoch BLOB NOT NULL,
    proof BLOB NOT NULL
)