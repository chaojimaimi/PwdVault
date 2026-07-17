use rand::{rngs::OsRng, Rng};

use crate::VaultError;

pub fn generate_password(
    length: usize,
    include_uppercase: bool,
    include_lowercase: bool,
    include_numbers: bool,
    include_symbols: bool,
) -> Result<String, VaultError> {
    crate::validation::generator(
        length,
        include_uppercase,
        include_lowercase,
        include_numbers,
        include_symbols,
    )?;

    let mut charset = String::new();
    let mut required_chars = Vec::new();

    // Collect all available character classes and their representatives
    if include_uppercase {
        charset.push_str("ABCDEFGHIJKLMNOPQRSTUVWXYZ");
        required_chars.push('A');
    }
    if include_lowercase {
        charset.push_str("abcdefghijklmnopqrstuvwxyz");
        required_chars.push('a');
    }
    if include_numbers {
        charset.push_str("0123456789");
        required_chars.push('0');
    }
    if include_symbols {
        charset.push_str("!@#$%^&*()_+-=[]{}|;:,.<>?");
        required_chars.push('!');
    }

    let mut rng = OsRng; // Use OS entropy source for better security
    let bytes: Vec<u8> = charset.bytes().collect();

    let num_required = required_chars.len();
    let mut password_chars: Vec<char> = required_chars;

    // Fill remaining positions with random characters from full charset
    for _ in 0..(length.saturating_sub(num_required)) {
        let idx = rng.gen_range(0..bytes.len());
        password_chars.push(bytes[idx] as char);
    }

    // Fisher-Yates shuffle to avoid predictable patterns (e.g., always starting with uppercase)
    let len = password_chars.len();
    for i in 0..len {
        let j = rng.gen_range(i..len);
        password_chars.swap(i, j);
    }

    Ok(password_chars.into_iter().collect())
}
