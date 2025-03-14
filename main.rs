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
use hex;

struct ScriptConfig {
    name: String,
    start_key: String,
    target_address: String,
    increment: String,
}

// RTX 4090 için optimize edilmiş CUDA kernel kodu
// sm_89 hedefini kullanıyoruz (RTX 4090 için)
const PTX_SRC: &str = r#"
.version 7.8
.target sm_89
.address_size 64

.visible .entry generate_keys(
    .param .u64 private_keys,
    .param .u64 start_key_high,
    .param .u64 start_key_low,
    .param .s32 increment_direction,
    .param .u64 step_size
)
{
    .reg .b32 	%r<5>;
    .reg .b64 	%rd<16>;

    ld.param.u64 	%rd1, [private_keys];
    ld.param.u64 	%rd4, [start_key_high];
    ld.param.u64 	%rd5, [start_key_low];
    ld.param.s32 	%r1, [increment_direction];
    ld.param.u64 	%rd6, [step_size];
    
    // Thread ID hesapla
    mov.u32 	%r2, %tid.x;
    mov.u32 	%r3, %ntid.x;
    mov.u32 	%r4, %ctaid.x;
    mad.lo.s32 	%r2, %r3, %r4, %r2;
    
    // Thread ID'yi 64-bit'e dönüştür
    cvt.u64.u32 	%rd7, %r2;
    // Thread ID * step_size
    mul.lo.u64 	%rd8, %rd7, %rd6;
    
    // Başlangıç değerlerini kopyala
    mov.u64 	%rd9, %rd5;  // low
    mov.u64 	%rd10, %rd4; // high
    
    // Artış yönüne göre hesapla
    setp.gt.s32 	%p1, %r1, 0;
    @%p1 bra 	$L__ADD;
    
    // Çıkarma işlemi
    setp.le.u64 	%p2, %rd8, %rd9;
    @%p2 bra 	$L__SUB_SIMPLE;
    
    // Karmaşık çıkarma (borrow gerekiyor)
    sub.u64 	%rd11, %rd8, %rd9;
    sub.u64 	%rd11, %rd11, 1;
    mov.u64 	%rd12, 0xFFFFFFFFFFFFFFFF;
    sub.u64 	%rd12, %rd12, %rd11;
    sub.u64 	%rd10, %rd10, 1;
    mov.u64 	%rd9, %rd12;
    bra.uni 	$L__STORE;
    
$L__ADD:
    // Toplama işlemi
    add.u64 	%rd13, %rd9, %rd8;
    setp.ge.u64 	%p3, %rd13, %rd9;
    @%p3 bra 	$L__ADD_SIMPLE;
    
    // Carry gerekiyor
    add.u64 	%rd10, %rd10, 1;
    mov.u64 	%rd9, %rd13;
    bra.uni 	$L__STORE;
    
$L__SUB_SIMPLE:
    // Basit çıkarma (borrow gerekmiyor)
    sub.u64 	%rd9, %rd9, %rd8;
    bra.uni 	$L__STORE;
    
$L__ADD_SIMPLE:
    // Basit toplama (carry gerekmiyor)
    mov.u64 	%rd9, %rd13;
    
$L__STORE:
    // Hesaplanan private key'i output buffer'a yaz
    mul.lo.u64 	%rd14, %rd7, 32;
    add.u64 	%rd15, %rd1, %rd14;
    
    // İlk 8 byte (high 64-bit)
    st.u64 	[%rd15], %rd10;
    
    // Sonraki 8 byte (low 64-bit)
    st.u64 	[%rd15+8], %rd9;
    
    // Geri kalan 16 byte'ı sıfırla
    st.u64 	[%rd15+16], 0;
    st.u64 	[%rd15+24], 0;
    
    ret;
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
    println!("CUDA başlatılıyor...");
    match rustacuda::init(CudaFlags::empty()) {
        Ok(_) => println!("CUDA başlatıldı."),
        Err(e) => {
            println!("CUDA başlatılamadı: {:?}", e);
            return Err(AppError::CudaError(e));
        }
    }
    
    // Cihaz kontrolü
    let device_count = Device::num_devices()?;
    println!("Bulunan CUDA cihazı sayısı: {}", device_count);
    
    if device_count == 0 {
        println!("CUDA destekli GPU bulunamadı!");
        return Err(AppError::Other("CUDA destekli GPU bulunamadı!".to_string()));
    }
    
    let device = Device::get_device(0)?;
    println!("GPU: {}", device.name()?);
    
    // Cihaz özelliklerini yazdır
    use rustacuda::device::DeviceAttribute;
    let major = device.get_attribute(DeviceAttribute::ComputeCapabilityMajor)?;
    let minor = device.get_attribute(DeviceAttribute::ComputeCapabilityMinor)?;
    println!("Compute Capability: {}.{}", major, minor);
    println!("Toplam bellek: {} MB", device.total_memory()? / 1024 / 1024);
    
    // Context oluştur
    println!("CUDA context oluşturuluyor...");
    let _context = Context::create_and_push(
        ContextFlags::MAP_HOST | ContextFlags::SCHED_AUTO, 
        device
    )?;
    println!("CUDA context oluşturuldu.");
    
    // PTX kodunu CString'e dönüştür
    println!("PTX kodu derleniyor...");
    let ptx_str = CString::new(PTX_SRC)?;
    println!("PTX kodu derlendi. Uzunluk: {} byte", PTX_SRC.len());
    
    // Modül yükle
    println!("CUDA modülü yükleniyor...");
    let module = Module::load_from_string(&ptx_str)?;
    println!("CUDA modülü yüklendi.");
    
    // Stream oluştur
    println!("CUDA stream oluşturuluyor...");
    let stream = Stream::new(StreamFlags::NON_BLOCKING, None)?;
    println!("CUDA stream oluşturuldu.");
    
    // RTX 4090 için optimize edilmiş parametreler
    const BLOCK_SIZE: u32 = 1024;  // RTX 4090 için maksimum thread sayısı
    const NUM_BLOCKS: u32 = 16384; // RTX 4090 için yüksek sayıda blok
    const TOTAL_THREADS: usize = (BLOCK_SIZE * NUM_BLOCKS) as usize;
    const STEP_SIZE: u64 = 1;      // Her thread kaç adım ilerleyecek
    
    println!("Kernel parametreleri:");
    println!("BLOCK_SIZE: {}", BLOCK_SIZE);
    println!("NUM_BLOCKS: {}", NUM_BLOCKS);
    println!("TOTAL_THREADS: {}", TOTAL_THREADS);
    println!("STEP_SIZE: {}", STEP_SIZE);
    
    // Taranacak adresler
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
    
    // Bulunan adres için atomik bayrak
    let found = Arc::new(AtomicBool::new(false));
    
    // GPU belleği ayır
    println!("GPU belleği ayrılıyor...");
    let mut device_private_keys = DeviceBuffer::from_slice(&vec![0u8; TOTAL_THREADS * 32])?;
    println!("GPU belleği ayrıldı.");
    
    // Host belleği
    let mut host_private_keys = vec![0u8; TOTAL_THREADS * 32];
    
    // Secp256k1 nesnesi
    let secp = Secp256k1::new();
    
    // Ana döngü
    let mut iteration = 0;
    let start_time = std::time::Instant::now();
    
    for script in &scripts {
        println!("Script {} başlatılıyor, başlangıç key: {}", script.name, script.start_key);
        
        // Başlangıç anahtarını hazırla
        let mut current_key = BigUint::from_str_radix(&script.start_key, 16).unwrap();
        
        // Artış yönü
        let increment_direction = if script.increment == "plus" { 1 } else { -1 };
        
        while !found.load(Ordering::Relaxed) {
            iteration += 1;
            
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
            
            // Kernel'i çağır
            unsafe {
                let function = module.get_function(&CString::new("generate_keys")?)?;
                launch!(function<<<NUM_BLOCKS, BLOCK_SIZE, 0, stream>>>(
                    device_private_keys.as_device_ptr(),
                    key_high,
                    key_low,
                    increment_direction,
                    STEP_SIZE
                ))?;
            }
            
            // GPU işleminin bitmesini bekle
            stream.synchronize()?;
            
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
            
            // Her 10 iterasyonda bir durum raporu
            if iteration % 10 == 0 {
                let elapsed = start_time.elapsed();
                let keys_per_second = (iteration * TOTAL_THREADS as u64) as f64 / elapsed.as_secs_f64();
                
                println!(
                    "Script: {}, İterasyon: {}, Toplam: {} key, Hız: {:.2} key/saniye, Şu anki key: {}", 
                    script.name,
                    iteration, 
                    iteration * TOTAL_THREADS as u64,
                    keys_per_second,
                    hex::encode(&padded)
                );
            }
        }
    }
    
    println!("İşlem tamamlandı!");
    Ok(())
} 