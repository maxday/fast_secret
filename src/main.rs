use std::time::SystemTime;
use time::OffsetDateTime;

use curl::easy::{Easy, List};
use std::io::{Read, Result};

use std::io::BufReader;

use ring::hmac::{self, Tag};

use ring::digest::{Context, Digest, SHA256};

const SERVICE_NAME: &str = "kms";
const AUTH_HEDER_PREFIX: &str = "AWS4-HMAC-SHA256";

fn main() {
    let region = std::env::var("AWS_REGION").unwrap();
    let function_name = std::env::var("AWS_LAMBDA_FUNCTION_NAME").unwrap();
    let encrypted_data = std::env::var("DD_KMS_API_KEY").unwrap();
    let current_time = SystemTime::now();

    let data = format!("{{\"CiphertextBlob\":\"{}\",\"EncryptionContext\":{{\"LambdaFunctionName\":\"{}\"}}}}", encrypted_data, function_name);
    let signature = build_signature(
        data.to_string(),
        format!("{}/{}/kms/aws4_request", format_date(current_time), region).to_string(),
        current_time,
    );
    let authorization_token = build_authorization_token(current_time, signature);
    send(current_time, data, authorization_token).unwrap();
}

pub fn build_signature(data: String, header: String, current_time: SystemTime) -> String {
    let region = std::env::var("AWS_REGION").unwrap();
    let secret_access_key = std::env::var("AWS_SECRET_ACCESS_KEY").unwrap();

    let creds = derive_signing_key(&region, SERVICE_NAME, &secret_access_key, current_time);

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

pub fn build_authorization_token(current_time: SystemTime, signature: String) -> String {
    let region = std::env::var("AWS_REGION").unwrap();
    let access_key_id = std::env::var("AWS_ACCESS_KEY_ID").unwrap();
    return format!("AWS4-HMAC-SHA256 Credential={}/{}/{}/kms/aws4_request, SignedHeaders=content-length;content-type;host;x-amz-date;x-amz-security-token;x-amz-target, Signature={}", access_key_id, format_date(current_time), region, signature);
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
    let region = std::env::var("AWS_REGION").unwrap();
    let reader = BufReader::new(body.as_bytes());
    let digest = sha256_digest(reader).unwrap();
    let session_token = std::env::var("AWS_SESSION_TOKEN").unwrap();
    let canonical_headers = format!("content-length:{}\ncontent-type:application/x-amz-json-1.1\nhost:kms.{}.amazonaws.com\nx-amz-date:{}\nx-amz-security-token:{}\nx-amz-target:TrentService.Decrypt\n", body.len(), region, format_date_time(current_time), session_token);
    let return_string = format!(
        "POST\n/\n\n{}\ncontent-length;content-type;host;x-amz-date;x-amz-security-token;x-amz-target\n{}",
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

fn send(current_time: SystemTime, data: String, authorization_token: String) -> Result<bool> {
    let region = std::env::var("AWS_REGION").unwrap();
    let session_token = std::env::var("AWS_SESSION_TOKEN").unwrap();
    let mut easy = Easy::new();
    easy.url(format!("https://kms.{}.amazonaws.com", region).as_str())?;
    easy.post(true)?;
    easy.post_field_size(data.len() as u64)?;

    let mut list = List::new();
    list.append("X-Amz-Target: TrentService.Decrypt")?;
    list.append("Content-Type: application/x-amz-json-1.1")?;
    list.append(format!("Content-Length: {}", data.len()).as_str())?;
    list.append(format!("X-Amz-Date: {}", format_date_time(current_time)).as_str())?;
    list.append(format!("Authorization: {}", authorization_token).as_str())?;
    list.append(format!("X-Amz-Security-Token: {}", session_token).as_str())?;

    easy.http_headers(list)?;

    easy.write_function(|data| {
        println!("{}", extract_data(data));
        Ok(data.len())
    })
    .unwrap();

    {
        let mut transfer = easy.transfer();
        transfer.read_function(|buf| Ok(data.as_bytes().read(buf).unwrap_or(0)))?;
        transfer.perform()?;
    }
    match easy.response_code() {
        Ok(code) => Ok(code < 300),
        Err(_) => Ok(false),
    }
}

pub fn extract_data(json_response: &[u8]) -> String {
    let json = std::str::from_utf8(json_response).unwrap().to_string();
    let res = json.find("\"Plaintext\"").unwrap();
    let plaintext = json[res..json.len()].to_string();
    let mut tokens = plaintext.split("\"");
    let result = tokens.nth(3).unwrap();
    let decoded = base64::decode(result).unwrap();
    std::str::from_utf8(&decoded).unwrap().to_string()
}