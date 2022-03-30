table! {
    proofs (id) {
        id -> Integer,
        first_epoch_index -> Integer,
        first_epoch -> Binary,
        last_epoch_index -> Integer,
        last_epoch -> Binary,
        proof -> Binary,
    }
}
