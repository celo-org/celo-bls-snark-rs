pub mod error;
pub mod handler;
pub mod models;
pub mod schema;
pub mod types;

#[macro_use]
extern crate diesel;

use diesel::sqlite::SqliteConnection;
use diesel::{prelude::*, result::Error::NotFound};
use dotenv::dotenv;
use eyre::Result;
use std::env;

use models::{NewProof, Proof};
use schema::proofs;

pub fn establish_connection() -> Result<SqliteConnection> {
    dotenv().ok();

    let database_url = env::var("DATABASE_URL")?;
    Ok(SqliteConnection::establish(&database_url)?)
}

pub fn create_proof(
    first_epoch_index: i32,
    first_epoch: &[u8],
    last_epoch_index: i32,
    last_epoch: &[u8],
    proof: &[u8],
) -> Result<()> {
    let connection = establish_connection()?;
    let new_proof = NewProof {
        first_epoch,
        first_epoch_index,
        last_epoch,
        last_epoch_index,
        proof,
    };

    diesel::insert_into(proofs::table)
        .values(&new_proof)
        .execute(&connection)?;

    Ok(())
}

pub fn get_existing_proof(start_epoch: i32, end_epoch: i32) -> Result<Option<Proof>> {
    use crate::proofs::dsl::*;

    let connection = establish_connection()?;
    let existing_proof = match proofs
        .filter(
            first_epoch_index
                .eq(start_epoch)
                .and(last_epoch_index.eq(end_epoch)),
        )
        .first::<Proof>(&connection)
    {
        Ok(p) => Some(p),
        Err(NotFound) => None,
        Err(e) => {
            return Err(e.into());
        }
    };

    Ok(existing_proof)
}

pub fn get_all_proofs() -> Result<Option<Vec<Proof>>> {
    use crate::proofs::dsl::*;

    let connection = establish_connection()?;
    let all_proofs = match proofs.load::<Proof>(&connection) {
        Ok(p) => Some(p),
        Err(NotFound) => None,
        Err(e) => {
            return Err(e.into());
        }
    };

    Ok(all_proofs)
}
