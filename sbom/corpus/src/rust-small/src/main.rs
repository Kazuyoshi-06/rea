use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug)]
struct Card { name: String, atk: u32 }

fn main() {
    let c: Card = serde_json::from_str(r#"{"name":"Ash Blossom","atk":0}"#).unwrap();
    println!("{}", serde_json::to_string(&c).unwrap());
}
