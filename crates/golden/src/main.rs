fn main() {
    println!("{}", serde_json::to_string_pretty(&golden::vectors()).unwrap());
}
