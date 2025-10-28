use aes_gcm::{
    Aes256Gcm, Key, Nonce,
    aead::{Aead, KeyInit},
};
use base64::{Engine as _, engine::general_purpose};
use pkcs8::DecodePrivateKey;
use rsa::{RsaPrivateKey, pkcs1v15::Pkcs1v15Encrypt};
use serde::{Deserialize, Serialize};
use serde_json;
use std::{fs, path::PathBuf};

use env_logger;
use futures::{Stream, TryStreamExt};
use std::{env, process, time::Duration};

use eventsource_client as es;

#[derive(Debug)]
enum AppError {
    Crypto(aes_gcm::Error),
    Io(std::io::Error),
    Rsa(rsa::Error),
    Pkcs8(pkcs8::Error),
    Base64(base64::DecodeError),
    Other(String),
}

impl std::fmt::Display for AppError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AppError::Crypto(err) => write!(f, "Cryptographic error: {}", err),
            AppError::Io(err) => write!(f, "IO error: {}", err),
            AppError::Rsa(err) => write!(f, "RSA error: {}", err),
            AppError::Pkcs8(err) => write!(f, "PKCS8 error: {}", err),
            AppError::Base64(err) => write!(f, "Base64 decode error: {}", err),
            AppError::Other(err) => write!(f, "Other error: {}", err),
        }
    }
}

impl std::error::Error for AppError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            AppError::Crypto(_) => None,
            AppError::Io(err) => Some(err),
            AppError::Rsa(err) => Some(err),
            AppError::Pkcs8(err) => Some(err),
            AppError::Base64(err) => Some(err),
            AppError::Other(_) => None,
        }
    }
}

impl From<aes_gcm::Error> for AppError {
    fn from(err: aes_gcm::Error) -> Self {
        AppError::Crypto(err)
    }
}

impl From<std::io::Error> for AppError {
    fn from(err: std::io::Error) -> Self {
        AppError::Io(err)
    }
}

impl From<rsa::Error> for AppError {
    fn from(err: rsa::Error) -> Self {
        AppError::Rsa(err)
    }
}

impl From<pkcs8::Error> for AppError {
    fn from(err: pkcs8::Error) -> Self {
        AppError::Pkcs8(err)
    }
}

impl From<base64::DecodeError> for AppError {
    fn from(err: base64::DecodeError) -> Self {
        AppError::Base64(err)
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
struct Payload {
    body: String,
    headers: String,
}

fn decrypt_asymmetric(
    to_decrypt_base64: &str,
    private_key_path: &PathBuf,
) -> Result<Vec<u8>, AppError> {
    let private_key_pem = fs::read_to_string(private_key_path)?;
    let private_key =
        RsaPrivateKey::from_pkcs8_pem(&private_key_pem).map_err(|e| AppError::Pkcs8(e.into()))?;

    let encrypted_bytes = general_purpose::STANDARD.decode(to_decrypt_base64)?;

    let padding = Pkcs1v15Encrypt;
    let decrypted = private_key.decrypt(padding, &encrypted_bytes)?;
    Ok(decrypted)
}

fn decrypt_symmetric(
    encrypted_string: &str,
    private_key_path: &PathBuf,
) -> Result<String, AppError> {
    let parts: Vec<&str> = encrypted_string.split(':').collect();
    if parts.len() != 3 {
        return Err(AppError::Other(
            "Invalid encrypted string format".to_string(),
        ));
    }

    let encrypted_symmetric_key_base64 = parts[0];
    let nonce_base64 = parts[1];
    let ciphertext_base64 = parts[2];

    // 1. Decrypt the symmetric key using asymmetric decryption
    let decrypted_symmetric_key_bytes =
        decrypt_asymmetric(encrypted_symmetric_key_base64, private_key_path)?;
    let key = Key::<Aes256Gcm>::from_slice(&decrypted_symmetric_key_bytes);
    let cipher = Aes256Gcm::new(key);

    // 2. Decode Nonce and ciphertext
    let nonce_bytes = general_purpose::STANDARD.decode(nonce_base64)?;
    let nonce = Nonce::from_slice(&nonce_bytes);
    let ciphertext = general_purpose::STANDARD.decode(ciphertext_base64)?;

    // 3. Decrypt the ciphertext
    let decrypted_text_bytes = cipher.decrypt(nonce, ciphertext.as_ref())?;
    Ok(String::from_utf8(decrypted_text_bytes)
        .map_err(|e| AppError::Other(format!("UTF-8 decode error: {}", e)))?)
}

#[tokio::main]
async fn main() -> Result<(), es::Error> {
    env_logger::init();

    let args: Vec<String> = env::args().collect();

    if args.len() != 3 {
        eprintln!("Please pass args: <url> <private_key_path>");
        process::exit(1);
    }

    let url = &args[1];
    let private_key_path = PathBuf::from(&args[2]);

    let client = es::ClientBuilder::for_url(url)?
        .reconnect(
            es::ReconnectOptions::reconnect(true)
                .retry_initial(false)
                .delay(Duration::from_secs(1))
                .backoff_factor(2)
                .delay_max(Duration::from_secs(60))
                .build(),
        )
        .build();

    let mut stream = tail_events(client, &private_key_path);

    while let Ok(Some(_)) = stream.try_next().await {}

    Ok(())
}

fn tail_events(
    client: impl es::Client,
    private_key_path: &PathBuf,
) -> impl Stream<Item = Result<(), ()>> {
    client
        .stream()
        .map_ok(move |event| match event {
            es::SSE::Connected(connection) => {
                eprintln!("connected status={}", connection.response().status())
            }
            es::SSE::Event(ev) => {
                match ev.event_type.as_str() {
                    "ping" => {} // Ignore
                    "webhook" => {
                        let data = general_purpose::STANDARD.decode(&ev.data).unwrap();
                        if let Ok(payload) = serde_json::from_slice::<Payload>(&data) {
                            match serde_json::to_string(&payload) {
                                Ok(payload) => {
                                    println!("{}", payload);
                                }
                                Err(e) => eprintln!("Webhook event unknown data: {}", e),
                            }
                        } else {
                            eprintln!("Webhook event unknown data: {:?}", data);
                        }
                    }
                    "encrypted" => {
                        let decrypted = decrypt_symmetric(&ev.data, &private_key_path).unwrap();
                        if let Ok(payload) = serde_json::from_slice::<Payload>(decrypted.as_bytes())
                        {
                            match serde_json::to_string(&payload) {
                                Ok(payload) => {
                                    println!("{}", payload);
                                }
                                Err(e) => eprintln!("Encrypted event unknown data: {}", e),
                            }
                        } else {
                            eprintln!("Encrypted event unknown data: {:?}", decrypted);
                        }
                    }
                    _ => eprintln!("got an unknown event: \n{:?}", ev),
                }
            }
            es::SSE::Comment(comment) => {
                eprintln!("got a comment: \n{}", comment)
            }
        })
        .map_err(|err| eprintln!("error streaming events: {:?}", err))
}
