use std::time::SystemTime;
use time::OffsetDateTime;

use curl::easy::{Easy, List};
use std::io::{Read, Result};
use std::io::BufReader;

use ring::hmac::{self, Tag};

use ring::digest::{Context, Digest, SHA256};

const AUTH_HEDER_PREFIX: &str = "AWS4-HMAC-SHA256";

pub struct AuthenticationContext {
    region: String,
    function_name: String,
    access_key_id: String,
    secret_access_key: String,
    session_token: String,
    current_time: SystemTime,
}

impl AuthenticationContext {
    pub fn new() -> AuthenticationContext {
        let region = std::env::var("AWS_REGION").expect("Could not find AWS_REGION value");
        let function_name = std::env::var("AWS_LAMBDA_FUNCTION_NAME").expect("Could not find AWS_LAMBDA_FUNCTION_NAME value");
        let access_key_id = std::env::var("AWS_ACCESS_KEY_ID").expect("Could not find AWS_ACCESS_KEY_ID value");
        let secret_access_key = std::env::var("AWS_SECRET_ACCESS_KEY").expect("Could not find AWS_SECRET_ACCESS_KEY value");
        let session_token = std::env::var("AWS_SESSION_TOKEN").expect("Could not find AWS_SESSION_TOKEN value");
        AuthenticationContext { 
            region,
            function_name,
            access_key_id,
            secret_access_key,
            session_token,
            current_time: SystemTime::now()
        }
    }
}

fn main() {
    let kms_api_key = std::env::var("DD_KMS_API_KEY").expect("Could not find DD_KMS_API_KEY");
    let auth_context = AuthenticationContext::new();
    let data = format!("{{\"CiphertextBlob\":\"{}\",\"EncryptionContext\":{{\"LambdaFunctionName\":\"{}\"}}}}", kms_api_key, auth_context.function_name);
    let signature = build_signature(
        data.to_string(),
        build_header(&auth_context),
        &auth_context,
    );
    let authorization_token = build_authorization_token(&auth_context, signature);
    send(&auth_context, data, authorization_token).unwrap();
}

pub fn build_header(auth_context: &AuthenticationContext) -> String {
    format!("{}/{}/kms/aws4_request", format_date(auth_context.current_time), auth_context.region).to_string()
}

pub fn build_signature(data: String, header: String, auth_context: &AuthenticationContext) -> String {
    let creds = derive_signing_key(auth_context);
    let canonical_string = build_canonical_string(auth_context, data);
    let reader = BufReader::new(canonical_string.as_bytes());
    let digest = sha256_digest(reader).unwrap();
    let string_to_sign = format!(
        "{}\n{}\n{}\n{}",
        AUTH_HEDER_PREFIX,
        format_date_time(auth_context.current_time),
        header,
        pretty_sha256(digest)
    );
    let key = hmac::Key::new(hmac::HMAC_SHA256, creds.as_ref());
    let signature = hmac::sign(&key, string_to_sign.as_bytes());
    pretty_tag(signature)
}

pub fn build_authorization_token(auth_context: &AuthenticationContext, signature: String) -> String {
    return format!("AWS4-HMAC-SHA256 Credential={}/{}/{}/kms/aws4_request, SignedHeaders=content-length;content-type;host;x-amz-date;x-amz-security-token;x-amz-target, Signature={}", auth_context.access_key_id, format_date(auth_context.current_time), auth_context.region, signature);
}

pub fn pretty_tag(tag: Tag) -> String {
    let pretty_format = format!("{:?}", tag);
    pretty_format[11..pretty_format.len() - 1].to_string()
}

pub fn pretty_sha256(digest: Digest) -> String {
    let pretty_format = format!("{:?}", digest);
    pretty_format[7..pretty_format.len()].to_string()
}

pub fn build_canonical_string(auth_context: &AuthenticationContext, body: String) -> String {
    let reader = BufReader::new(body.as_bytes());
    let digest = sha256_digest(reader).unwrap();
    let canonical_headers = format!("content-length:{}\ncontent-type:application/x-amz-json-1.1\nhost:kms.{}.amazonaws.com\nx-amz-date:{}\nx-amz-security-token:{}\nx-amz-target:TrentService.Decrypt\n", body.len(), auth_context.region, format_date_time(auth_context.current_time),auth_context.session_token);
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

pub fn derive_signing_key(auth_context: &AuthenticationContext) -> hmac::Tag {
    let secret = format!("AWS4{}", auth_context.secret_access_key);
    let key = hmac::Key::new(hmac::HMAC_SHA256, secret.as_bytes());
    let date_tag = hmac::sign(&key, format_date(auth_context.current_time).as_bytes());
    let key = hmac::Key::new(hmac::HMAC_SHA256, date_tag.as_ref());
    let region_tag = hmac::sign(&key, auth_context.region.as_bytes());
    let key = hmac::Key::new(hmac::HMAC_SHA256, region_tag.as_ref());
    let kms_tag = hmac::sign(&key, "kms".as_bytes());
    let key = hmac::Key::new(hmac::HMAC_SHA256, kms_tag.as_ref());
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

fn send(auth_context: &AuthenticationContext, data: String, authorization_token: String) -> Result<bool> {
    let mut easy = Easy::new();
    easy.url(format!("https://kms.{}.amazonaws.com", auth_context.region).as_str())?;
    easy.post(true)?;
    easy.post_field_size(data.len() as u64)?;

    let mut list = List::new();
    list.append("X-Amz-Target: TrentService.Decrypt")?;
    list.append("Content-Type: application/x-amz-json-1.1")?;
    list.append(format!("Content-Length: {}", data.len()).as_str())?;
    list.append(format!("X-Amz-Date: {}", format_date_time(auth_context.current_time)).as_str())?;
    list.append(format!("Authorization: {}", authorization_token).as_str())?;
    list.append(format!("X-Amz-Security-Token: {}", auth_context.session_token).as_str())?;

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