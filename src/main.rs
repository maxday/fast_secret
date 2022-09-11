use std::time::SystemTime;
use time::OffsetDateTime;

use curl::easy::{Easy, List};

use std::io::stdout;
use std::io::Write;
use std::io::{Read, Result};

use std::io::BufReader;

use ring::hmac::{self, Tag};

use ring::digest::{Context, Digest, SHA256};

const REGION: &str = "us-east-1";
const SERVICE_NAME: &str = "kms";
const SECRET_ACCESS_KEY: &str = "YHlRKoA53PUHMA+qxWDL6pXBiGuw9+k4Y0Ilzr/H";
const AUTH_HEDER_PREFIX: &str = "AWS4-HMAC-SHA256";

fn main() {
    let current_time = SystemTime::now();
    let data = "{\"CiphertextBlob\":\"AQICAHicZZM/gbA5Dy16gHH+DsBSqIWFNpchG6RdjVjemTte6AHxU/ZvRbmqrtVthi/nSO0rAAAAYjBgBgkqhkiG9w0BBwagUzBRAgEAMEwGCSqGSIb3DQEHATAeBglghkgBZQMEAS4wEQQMWbAa7s6RTm548/liAgEQgB9GCHlXeBaLt1OkwIN0i275tcMHNuMzcybSR5FN/bQn\",\"EncryptionContext\":{\"LambdaFunctionName\":\"lambda-perf-provided\"}}";
    let signature = build_signature(
        data.to_string(),
        "20220911/us-east-1/kms/aws4_request".to_string(),
        current_time,
    );
    println!("signature = {}", signature);
    let authorization_token = build_authorization_token(signature);
    println!("authorization_token = {}", authorization_token);
    send(current_time, authorization_token).unwrap();
}

pub fn build_signature(data: String, header: String, current_time: SystemTime) -> String {
    let creds = derive_signing_key(REGION, SERVICE_NAME, SECRET_ACCESS_KEY, current_time);

    println!("CRED = {}", pretty_tag(creds));

    let canonical_string = build_canonical_string(current_time, data);
    let reader = BufReader::new(canonical_string.as_bytes());
    let digest = sha256_digest(reader).unwrap();
    let string_to_sign = format!(
        "{}\n{}\n{}\n{}",
        AUTH_HEDER_PREFIX,
        format_date_time(current_time),
        header,
        pretty_sha256(digest)
    );
    let key = hmac::Key::new(hmac::HMAC_SHA256, creds.as_ref());
    let signature = hmac::sign(&key, string_to_sign.as_bytes());
    pretty_tag(signature)
}

pub fn build_authorization_token(signature: String) -> String {
    return format!("AWS4-HMAC-SHA256 Credential=AKIATVJA2RVZV5PFGXUP/20220911/us-east-1/kms/aws4_request, SignedHeaders=content-length;content-type;host;x-amz-date;x-amz-target, Signature={}", signature);
}

pub fn pretty_tag(tag: Tag) -> String {
    let pretty_format = format!("{:?}", tag);
    pretty_format[11..pretty_format.len() - 1].to_string()
}

pub fn pretty_sha256(digest: Digest) -> String {
    let pretty_format = format!("{:?}", digest);
    pretty_format[7..pretty_format.len()].to_string()
}

pub fn build_canonical_string(current_time: SystemTime, body: String) -> String {
    let reader = BufReader::new(body.as_bytes());
    let digest = sha256_digest(reader).unwrap();
    let canonical_headers = format!("content-length:295\ncontent-type:application/x-amz-json-1.1\nhost:kms.us-east-1.amazonaws.com\nx-amz-date:{}\nx-amz-target:TrentService.Decrypt\n", format_date_time(current_time));
    let return_string = format!(
        "POST\n/\n\n{}\ncontent-length;content-type;host;x-amz-date;x-amz-target\n{}",
        canonical_headers,
        pretty_sha256(digest)
    );
    return_string
}

fn sha256_digest<R: Read>(mut reader: R) -> Result<Digest> {
    let mut context = Context::new(&SHA256);
    let mut buffer = [0; 1024];

    loop {
        let count = reader.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        context.update(&buffer[..count]);
    }
    Ok(context.finish())
}

pub fn derive_signing_key(
    region: &str,
    service: &str,
    secret: &str,
    time: SystemTime,
) -> hmac::Tag {
    let secret = format!("AWS4{}", secret);
    let secret = hmac::Key::new(hmac::HMAC_SHA256, secret.as_bytes());
    let tag = hmac::sign(&secret, format_date(time).as_bytes());

    // sign region
    let key = hmac::Key::new(hmac::HMAC_SHA256, tag.as_ref());
    let tag = hmac::sign(&key, region.as_bytes());

    // sign service
    let key = hmac::Key::new(hmac::HMAC_SHA256, tag.as_ref());
    let tag = hmac::sign(&key, service.as_bytes());

    // sign request
    let key = hmac::Key::new(hmac::HMAC_SHA256, tag.as_ref());
    hmac::sign(&key, "aws4_request".as_bytes())
}

pub fn format_date(time: SystemTime) -> String {
    let time = OffsetDateTime::from(time);
    format!(
        "{:04}{:02}{:02}",
        time.year(),
        u8::from(time.month()),
        time.day()
    )
}

pub fn format_date_time(time: SystemTime) -> String {
    let time = OffsetDateTime::from(time);
    format!(
        "{:04}{:02}{:02}T{:02}{:02}{:02}Z",
        time.year(),
        u8::from(time.month()),
        time.day(),
        time.hour(),
        time.minute(),
        time.second()
    )
}

fn send(current_time: SystemTime, authorization_token: String) -> Result<bool> {
    let mut data = "{\"CiphertextBlob\":\"AQICAHicZZM/gbA5Dy16gHH+DsBSqIWFNpchG6RdjVjemTte6AHxU/ZvRbmqrtVthi/nSO0rAAAAYjBgBgkqhkiG9w0BBwagUzBRAgEAMEwGCSqGSIb3DQEHATAeBglghkgBZQMEAS4wEQQMWbAa7s6RTm548/liAgEQgB9GCHlXeBaLt1OkwIN0i275tcMHNuMzcybSR5FN/bQn\",\"EncryptionContext\":{\"LambdaFunctionName\":\"lambda-perf-provided\"}}".as_bytes();
    let mut easy = Easy::new();
    easy.url("https://kms.us-east-1.amazonaws.com")?;
    easy.post(true)?;
    easy.post_field_size(data.len() as u64)?;

    let mut list = List::new();
    list.append("X-Amz-Target: TrentService.Decrypt")?;
    list.append("Content-Type: application/x-amz-json-1.1")?;
    list.append("Content-Length: 295")?;
    list.append(format!("X-Amz-Date: {}", format_date_time(current_time)).as_str())?;
    list.append(format!("Authorization: {}", authorization_token).as_str())?;

    easy.http_headers(list)?;

    easy.write_function(|data| {
        stdout().write_all(data).unwrap();
        Ok(data.len())
    })
    .unwrap();

    {
        let mut transfer = easy.transfer();
        transfer.read_function(|buf| Ok(data.read(buf).unwrap_or(0)))?;
        transfer.perform()?;
    }
    match easy.response_code() {
        Ok(code) => Ok(code < 300),
        Err(_) => Ok(false),
    }
}
