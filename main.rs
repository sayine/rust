use bitcoin::{Address, Network, PrivateKey, PublicKey};
use bitcoin::secp256k1::Secp256k1;
use rayon::prelude::*;
use num_bigint::BigUint;
use num_traits::Num;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use lettre::transport::smtp::authentication::Credentials;
use lettre::{Message, SmtpTransport, Transport};

struct ScriptConfig {
    name: String,
    start_key: String,
    target_address: String,
    increment: String,
}

fn pad_to_32_bytes(bytes: Vec<u8>) -> Vec<u8> {
    let mut padded = vec![0; 32];
    let start = if bytes.len() > 32 { bytes.len() - 32 } else { 0 };
    let copy_len = std::cmp::min(bytes.len(), 32);
    let dest_start = 32 - copy_len;
    padded[dest_start..].copy_from_slice(&bytes[start..start + copy_len]);
    padded
}

fn send_email(private_key: &str, address: &str) {
    let email = Message::builder()
        .from("nodejs577@gmail.com".parse().unwrap())
        .to("emrahsayin@yandex.com".parse().unwrap())
        .subject("Bitcoin Address Bulundu!")
        .body(format!("Private Key: {}\nAddress: {}", private_key, address))
        .unwrap();

    let creds = Credentials::new(
        "nodejs577@gmail.com".to_string(),
        "khve hbqo fdgv ygdh".to_string()
    );

    let mailer = SmtpTransport::relay("smtp.gmail.com")
        .unwrap()
        .credentials(creds)
        .build();

    match mailer.send(&email) {
        Ok(_) => println!("Email başarıyla gönderildi!"),
        Err(e) => println!("Email gönderilemedi: {:?}", e),
    }
}

fn main() {
    let cpus = num_cpus::get() - 1;
    let cpus_per_script = cpus / 2;

    let scripts = vec![
        ScriptConfig {
            name: String::from("67M"),
            start_key: String::from("9047cd2e41b3231de"),
            target_address: String::from("1MVDYgVaSN6iKKEsbzRUAYFrYJadLYZvvZ"),
            increment: String::from("minus"),
        },
        ScriptConfig {
            name: String::from("67P"),
            start_key: String::from("9047cd2f1efb528df"),
            target_address: String::from("1MVDYgVaSN6iKKEsbzRUAYFrYJadLYZvvZ"),
            increment: String::from("plus"),
        },
    ];

    let found = Arc::new(AtomicBool::new(false));
    let secp = Secp256k1::new();

    scripts.par_iter().for_each(|script| {
        let found = Arc::clone(&found);
        let mut counter = 0;
        let mut i = BigUint::from_str_radix(&script.start_key, 16).unwrap();
        
        while !found.load(Ordering::Relaxed) {
            // Address kontrolü
            let bytes = pad_to_32_bytes(i.to_bytes_be());
            
            // Private key oluşturma denemesi
            match PrivateKey::from_slice(&bytes, Network::Bitcoin) {
                Ok(private_key) => {
                    let public_key = PublicKey::from_private_key(&secp, &private_key);
                    let address = Address::p2pkh(&public_key, Network::Bitcoin);

                    if address.to_string() == script.target_address {
                        found.store(true, Ordering::Relaxed);
                        let priv_key_hex = hex::encode(private_key.to_bytes());
                        println!("Bulundu! Script: {}", script.name);
                        println!("Address: {}", address);
                        println!("Private Key: {}", priv_key_hex);
                        
                        // Email gönder
                        send_email(&priv_key_hex, &address.to_string());
                        break;
                    }
                },
                Err(_) => {
                    // Geçersiz private key, devam et
                }
            }

            // Sayaç kontrolü
            if counter % 660000 == 0 {
                println!("{}: {}", script.name, hex::encode(&bytes));
            }
            counter += 1;

            // Increment/decrement
            match script.increment.as_str() {
                "plus" => i += 2u32 * cpus_per_script as u32,
                "minus" => i -= 2u32 * cpus_per_script as u32,
                _ => {}
            }
        }
    });
} 