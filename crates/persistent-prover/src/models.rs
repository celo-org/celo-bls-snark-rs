use crate::schema::proofs;

#[derive(Queryable)]
pub struct Proof {
    pub id: i32,
    pub first_epoch_index: i32,
    pub first_epoch: Vec<u8>,
    pub last_epoch_index: i32,
    pub last_epoch: Vec<u8>,
    pub proof: Vec<u8>,
}

#[derive(Insertable)]
#[table_name = "proofs"]
pub struct NewProof<'a> {
    pub first_epoch_index: i32,
    pub first_epoch: &'a [u8],
    pub last_epoch_index: i32,
    pub last_epoch: &'a [u8],
    pub proof: &'a [u8],
}
