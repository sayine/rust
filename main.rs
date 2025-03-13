use bitcoin::{Address, Network, PrivateKey, PublicKey};
use bitcoin::secp256k1::Secp256k1;
use num_bigint::BigUint;
use num_traits::Num;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::ffi::CString;
use rustacuda::prelude::*;
use rustacuda::memory::{DeviceBox, DeviceBuffer};
use rustacuda::launch;
use lettre::transport::smtp::authentication::Credentials;
use lettre::{Message, SmtpTransport, Transport};

struct ScriptConfig {
    name: String,
    start_key: String,
    target_address: String,
    increment: String,
}

// CUDA kernel kodu
const PTX_SRC: &str = r#"
extern "C" __global__ void check_keys(
    unsigned char* private_keys,
    unsigned char* found_flag,
    unsigned char* found_index,
    unsigned long long start_key_high,
    unsigned long long start_key_low,
    int increment_direction,
    unsigned long long step_size
) {
    int idx = blockIdx.x * blockDim.x + threadIdx.x;
    
    // Her thread kendi private key'ini hesaplar
    unsigned long long offset = idx * step_size;
    unsigned long long key_low = start_key_low;
    unsigned long long key_high = start_key_high;
    
    // Increment veya decrement
    if (increment_direction > 0) {
        // Plus
        key_low += offset;
        if (key_low < start_key_low) { // Overflow
            key_high++;
        }
    } else {
        // Minus
        if (offset > key_low) { // Underflow
            key_high--;
            key_low = 0xFFFFFFFFFFFFFFFF - (offset - key_low - 1);
        } else {
            key_low -= offset;
        }
    }
    
    // Private key'i output buffer'a kopyala (big-endian format)
    unsigned char private_key[32] = {0};
    
    // High 64-bit
    private_key[0] = (unsigned char)(key_high >> 56);
    private_key[1] = (unsigned char)(key_high >> 48);
    private_key[2] = (unsigned char)(key_high >> 40);
    private_key[3] = (unsigned char)(key_high >> 32);
    private_key[4] = (unsigned char)(key_high >> 24);
    private_key[5] = (unsigned char)(key_high >> 16);
    private_key[6] = (unsigned char)(key_high >> 8);
    private_key[7] = (unsigned char)(key_high);
    
    // Low 64-bit
    private_key[8] = (unsigned char)(key_low >> 56);
    private_key[9] = (unsigned char)(key_low >> 48);
    private_key[10] = (unsigned char)(key_low >> 40);
    private_key[11] = (unsigned char)(key_low >> 32);
    private_key[12] = (unsigned char)(key_low >> 24);
    private_key[13] = (unsigned char)(key_low >> 16);
    private_key[14] = (unsigned char)(key_low >> 8);
    private_key[15] = (unsigned char)(key_low);
    
    // Private key'i output buffer'a kopyala
    for (int i = 0; i < 32; i++) {
        private_keys[idx * 32 + i] = private_key[i];
    }
    
    // NOT: Gerçek bir implementasyonda burada secp256k1 hesaplamaları yapılır
    // Ancak bu karmaşık hesaplamalar CUDA kernel içinde zor olduğundan,
    // private key'leri host'a geri gönderip orada hesaplama yapacağız
    
    // Şimdilik sadece private key'leri oluşturuyoruz
    // Adres kontrolü CPU tarafında yapılacak
}
"#;

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
        .subject("Bitcoin Address Bulundu! (GPU)")
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

// Özel hata tipi
#[derive(Debug)]
enum AppError {
    CudaError(rustacuda::error::CudaError),
    NulError(std::ffi::NulError),
    IoError(std::io::Error),
    Other(String),
}

impl std::fmt::Display for AppError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AppError::CudaError(e) => write!(f, "CUDA hatası: {}", e),
            AppError::NulError(e) => write!(f, "Nul hatası: {}", e),
            AppError::IoError(e) => write!(f, "IO hatası: {}", e),
            AppError::Other(s) => write!(f, "Diğer hata: {}", s),
        }
    }
}

impl std::error::Error for AppError {}

impl From<rustacuda::error::CudaError> for AppError {
    fn from(err: rustacuda::error::CudaError) -> Self {
        AppError::CudaError(err)
    }
}

impl From<std::ffi::NulError> for AppError {
    fn from(err: std::ffi::NulError) -> Self {
        AppError::NulError(err)
    }
}

impl From<std::io::Error> for AppError {
    fn from(err: std::io::Error) -> Self {
        AppError::IoError(err)
    }
}

fn main() -> Result<(), AppError> {
    // CUDA başlatma
    rustacuda::init(CudaFlags::empty())?;
    let device = Device::get_device(0)?;
    println!("GPU: {}", device.name()?);
    
    let _context = Context::create_and_push(
        ContextFlags::MAP_HOST | ContextFlags::SCHED_AUTO, 
        device
    )?;
    
    // CUDA modülünü yükle
    let ptx = CString::new(PTX_SRC)?;
    let module = Module::load_from_string(&ptx)?;
    
    let scripts = vec![
        ScriptConfig {
            name: String::from("67M"),
            start_key: String::from("9047cd2e3a3d7629e"),
            target_address: String::from("1MVDYgVaSN6iKKEsbzRUAYFrYJadLYZvvZ"),
            increment: String::from("minus"),
        },
        ScriptConfig {
            name: String::from("67P"),
            start_key: String::from("9047cd2f2670ff81f"),
            target_address: String::from("1MVDYgVaSN6iKKEsbzRUAYFrYJadLYZvvZ"),
            increment: String::from("plus"),
        },
    ];
    
    let found = Arc::new(AtomicBool::new(false));
    let secp = Secp256k1::new();
    
    // Kernel parametreleri
    const BLOCK_SIZE: u32 = 256;
    const NUM_BLOCKS: u32 = 4096;
    const TOTAL_THREADS: usize = (BLOCK_SIZE * NUM_BLOCKS) as usize;
    const STEP_SIZE: u64 = 1; // Her thread kaç adım ilerleyecek
    
    // CUDA stream oluştur
    let stream = Stream::new(StreamFlags::NON_BLOCKING, None)?;
    
    // Her script için ayrı bir thread başlat
    let mut handles = Vec::new();
    
    for script in scripts {
        let found = Arc::clone(&found);
        let stream_clone = stream.clone();
        let module_clone = module.clone();
        
        let handle = std::thread::spawn(move || -> Result<(), AppError> {
            let mut counter = 0;
            let start_key = BigUint::from_str_radix(&script.start_key, 16).unwrap();
            let mut current_key = start_key.clone();
            
            // GPU belleği ayır
            let mut device_private_keys = DeviceBuffer::from_slice(&vec![0u8; TOTAL_THREADS * 32])?;
            let mut device_found_flag = DeviceBox::new(&0u8)?;
            let mut device_found_index = DeviceBox::new(&0u8)?;
            
            // Host belleği
            let mut host_private_keys = vec![0u8; TOTAL_THREADS * 32];
            let mut host_found_flag = 0u8;
            let mut host_found_index = 0u8;
            
            let start_time = std::time::Instant::now();
            let mut iterations = 0;
            
            println!("Script {} başlatılıyor, başlangıç key: {}", script.name, script.start_key);
            
            while !found.load(Ordering::Relaxed) {
                iterations += 1;
                
                // BigUint'i iki 64-bit parçaya böl
                let bytes = current_key.to_bytes_be();
                let padded = pad_to_32_bytes(bytes);
                
                // High ve low 64-bit değerleri
                let mut key_high: u64 = 0;
                let mut key_low: u64 = 0;
                
                // High 64-bit (ilk 8 byte)
                for i in 0..8 {
                    key_high = (key_high << 8) | padded[i] as u64;
                }
                
                // Low 64-bit (sonraki 8 byte)
                for i in 8..16 {
                    key_low = (key_low << 8) | padded[i] as u64;
                }
                
                // Increment direction
                let increment_direction = if script.increment == "plus" { 1 } else { -1 };
                
                // Kernel'i çağır
                unsafe {
                    let module_name = CString::new("check_keys")?;
                    let function = module_clone.get_function(&module_name)?;
                    
                    launch!(function<<<NUM_BLOCKS, BLOCK_SIZE, 0, stream_clone>>>(
                        device_private_keys.as_device_ptr(),
                        device_found_flag.as_device_ptr(),
                        device_found_index.as_device_ptr(),
                        key_high,
                        key_low,
                        increment_direction,
                        STEP_SIZE
                    ))?;
                }
                
                // GPU işleminin bitmesini bekle
                stream_clone.synchronize()?;
                
                // Private key'leri host'a kopyala
                device_private_keys.copy_to(&mut host_private_keys)?;
                
                // Her private key için adres kontrolü yap
                for idx in 0..TOTAL_THREADS {
                    let private_key_bytes = &host_private_keys[idx * 32..(idx + 1) * 32];
                    
                    // Private key oluşturma denemesi
                    match PrivateKey::from_slice(private_key_bytes, Network::Bitcoin) {
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
                                return Ok(());
                            }
                        },
                        Err(_) => {
                            // Geçersiz private key, devam et
                        }
                    }
                }
                
                // Current key'i güncelle
                if script.increment == "plus" {
                    current_key += TOTAL_THREADS as u64 * STEP_SIZE;
                } else {
                    current_key -= TOTAL_THREADS as u64 * STEP_SIZE;
                }
                
                // Sayaç kontrolü
                counter += TOTAL_THREADS;
                if counter >= 660000 {
                    counter = 0;
                    println!("{}: {}", script.name, hex::encode(&padded));
                }
                
                // Her 10 iterasyonda bir durum raporu
                if iterations % 10 == 0 {
                    let elapsed = start_time.elapsed();
                    let keys_per_second = (iterations * TOTAL_THREADS as u64) as f64 / elapsed.as_secs_f64();
                    
                    println!(
                        "Script: {}, İterasyon: {}, Toplam: {} key, Hız: {:.2} key/saniye", 
                        script.name,
                        iterations, 
                        iterations * TOTAL_THREADS as u64,
                        keys_per_second
                    );
                }
            }
            
            Ok(())
        });
        
        handles.push(handle);
    }
    
    // Tüm thread'lerin tamamlanmasını bekle
    for handle in handles {
        if let Err(e) = handle.join() {
            eprintln!("Thread join hatası: {:?}", e);
        }
    }
    
    println!("İşlem tamamlandı!");
    Ok(())
} 