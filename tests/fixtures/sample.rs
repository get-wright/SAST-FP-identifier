use std::io;
use std::collections::HashMap;

fn process_input(input: &str) -> String {
    let trimmed = input.trim();
    format!("processed: {}", trimmed)
}

fn validate_and_store(data: &str) {
    let result = parse_data(data);
    store_result(&result);
}

struct UserService {
    db: HashMap<String, String>,
}

impl UserService {
    fn get_user(&self, id: &str) -> Option<&String> {
        self.db.get(id)
    }
}
