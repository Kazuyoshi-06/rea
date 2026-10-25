fn main() {
    let re = regex::Regex::new(r"^\d{8}$").unwrap();
    println!("{}", re.is_match("89631139"));
}
