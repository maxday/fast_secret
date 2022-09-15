use std::time::SystemTime;
use std::io::{Read, Result};
use std::io::BufReader;

use time::OffsetDateTime;

use curl::easy::{Easy, List};

use ring::hmac::{self};
use ring::digest::{Context, Digest, SHA256};

const ENV_REGION: &str = "AWS_REGION";
const ENV_FUNCTION_NAME: &str = "AWS_LAMBDA_FUNCTION_NAME";
const ENV_ACCESS_KEY: &str = "AWS_ACCESS_KEY_ID";
const ENV_SECRET_KEY: &str = "AWS_SECRET_ACCESS_KEY";
const ENV_SESSION_TOKEN: &str = "AWS_SESSION_TOKEN";

const AUTH_HEDER_PREFIX: &str = "AWS4-HMAC-SHA256";

pub struct AuthenticationContext {
    region: String,
    function_name: String,
    access_key_id: String,
    secret_access_key: String,
    session_token: String,
    date: String,
    date_time: String,
}

impl AuthenticationContext {
    pub fn new() -> AuthenticationContext {
        let region = std::env::var(ENV_REGION).expect("Could not find AWS_REGION value");
        let function_name = std::env::var(ENV_FUNCTION_NAME).expect("Could not find AWS_LAMBDA_FUNCTION_NAME value");
        let access_key_id = std::env::var(ENV_ACCESS_KEY).expect("Could not find AWS_ACCESS_KEY_ID value");
        let secret_access_key = std::env::var(ENV_SECRET_KEY).expect("Could not find AWS_SECRET_ACCESS_KEY value");
        let session_token = std::env::var(ENV_SESSION_TOKEN).expect("Could not find AWS_SESSION_TOKEN value");
        let current_time = SystemTime::now();
        AuthenticationContext { 
            region,
            function_name,
            access_key_id,
            secret_access_key,
            session_token,
            date: format_date(current_time),
            date_time: format_date_time(current_time),
        }
    }

    #[cfg(test)]
    fn with_time(date: &str, date_time: &str) -> AuthenticationContext {
        let context = AuthenticationContext::new();
        AuthenticationContext {
            region: context.region,
            function_name: context.function_name,
            access_key_id: context.access_key_id,
            secret_access_key: context.secret_access_key,
            session_token: context.session_token,
            date: date.to_string(),
            date_time: date_time.to_string(),
        }
    }
}

fn main() {
    let cipher_blob = std::env::var("DD_KMS_API_KEY").expect("Could not find DD_KMS_API_KEY");
    println!("{:?}", decrypt(cipher_blob.as_str(), false));
}

pub fn decrypt(cipher_blob: &str, full_json: bool) -> Result<String> {
    let auth_context = AuthenticationContext::new();
    let function_name = auth_context.function_name.clone();
    let payload = build_payload(cipher_blob, function_name.as_str());
    let api_result = send(&auth_context, payload.as_str())?;
    return Ok(format_response(&api_result, full_json))
}

//tested
pub fn build_payload(cipher_blob: &str, function_name: &str) -> String {
    return format!("{{\"CiphertextBlob\":\"{}\",\"EncryptionContext\":{{\"LambdaFunctionName\":\"{}\"}}}}", cipher_blob, function_name);
} 

//tested
pub fn build_header(auth_context: &AuthenticationContext) -> String {
    format!("{}/{}/kms/aws4_request", auth_context.date, auth_context.region)
}

//tested
pub fn build_signature(data: &str, header: String, auth_context: &AuthenticationContext) -> String {
    let creds = derive_signing_key(auth_context);
    let canonical_string = build_canonical_string(auth_context, data);
    let reader = BufReader::new(canonical_string.as_bytes());
    let digest = sha256_digest(reader).unwrap();
    let hex_digest = hex::encode(digest);

    let string_to_sign = format!(
        "{}\n{}\n{}\n{}",
        AUTH_HEDER_PREFIX,
        auth_context.date_time,
        header,
        hex_digest
    );
    let key = hmac::Key::new(hmac::HMAC_SHA256, creds.as_ref());
    let signature = hmac::sign(&key, string_to_sign.as_bytes());
    return hex::encode(signature);
}

// tested
pub fn build_authorization_token(auth_context: &AuthenticationContext, signature: String) -> String {
    return format!("AWS4-HMAC-SHA256 Credential={}/{}/{}/kms/aws4_request, SignedHeaders=content-length;content-type;host;x-amz-date;x-amz-security-token;x-amz-target, Signature={}", auth_context.access_key_id, auth_context.date, auth_context.region, signature);
}

// tested
pub fn build_canonical_string(auth_context: &AuthenticationContext, body: &str) -> String {
    let reader = BufReader::new(body.as_bytes());
    let digest = sha256_digest(reader).unwrap();
    let canonical_headers = format!("content-length:{}\ncontent-type:application/x-amz-json-1.1\nhost:kms.{}.amazonaws.com\nx-amz-date:{}\nx-amz-security-token:{}\nx-amz-target:TrentService.Decrypt\n", body.len(), auth_context.region,auth_context.date_time,auth_context.session_token);
    let return_string = format!(
        "POST\n/\n\n{}\ncontent-length;content-type;host;x-amz-date;x-amz-security-token;x-amz-target\n{}",
        canonical_headers,
        hex::encode(digest)
    );
    return_string
}

// tested
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
    let date_tag = hmac::sign(&key, auth_context.date.as_bytes());
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

//tested
fn build_header_list(auth_context: &AuthenticationContext, payload: &str) -> Result<List> {
    let content_length = payload.len();
    let signature = build_signature( payload,
        build_header(&auth_context),
        &auth_context,
    );
    let authorization_token = build_authorization_token(&auth_context, signature);
    let mut list = List::new();
    list.append("X-Amz-Target: TrentService.Decrypt")?;
    list.append("Content-Type: application/x-amz-json-1.1")?;
    list.append(format!("Content-Length: {}", content_length).as_str())?;
    list.append(format!("X-Amz-Date: {}", auth_context.date_time).as_str())?;
    list.append(format!("Authorization: {}", authorization_token).as_str())?;
    list.append(format!("X-Amz-Security-Token: {}", auth_context.session_token).as_str())?;
    Ok(list)
}

fn send(auth_context: &AuthenticationContext, data: &str) -> Result<Vec<u8>> {
    let mut easy = Easy::new();
    let mut dst = Vec::new();
    {
        easy.url(format!("https://kms.{}.amazonaws.com", auth_context.region).as_str())?;
        easy.post(true)?;
        easy.post_field_size(data.len() as u64)?;
        easy.http_headers(build_header_list(auth_context, data)?)?;

        let mut transfer = easy.transfer();
        
        transfer.read_function(|buf| Ok(data.as_bytes().read(buf).unwrap_or(0)))?;
        
        transfer.write_function(|result_data| {
            dst.extend_from_slice(result_data);
            Ok(result_data.len())
        })?;
        
        transfer.perform()?;
    }
    return Ok(dst);
}

pub fn format_response(json_response: &[u8], full_json: bool) -> String {
    let json = String::from_utf8_lossy(json_response);
    if full_json {
        return json.to_string();
    }
    let res = json.find("\"Plaintext\"").unwrap();
    let plaintext = json[res..json.len()].to_string();
    let mut tokens = plaintext.split("\"");
    let result = tokens.nth(3).unwrap();
    let decoded = base64::decode(result).unwrap();
    std::str::from_utf8(&decoded).unwrap().to_string()
}

#[cfg(test)]
mod tests {

    use super::*;
 
    #[test]
    fn test_build_payload() {
        let cipher_blob = "abc";
        let function_name = "my_function";
        assert_eq!("{\"CiphertextBlob\":\"abc\",\"EncryptionContext\":{\"LambdaFunctionName\":\"my_function\"}}", build_payload(cipher_blob, function_name));
    }

    #[test]
    fn test_build_header() {
        set_test_env();
        let auth_context = AuthenticationContext::with_time("20220101", "20220101T010203Z");
        let result = build_header(&auth_context);
        let expected = "20220101/test-region/kms/aws4_request";
        unset_test_env();
        assert_eq!(expected, result);
    }

    #[test]
    fn test_build_authorization_token() {
        set_test_env();
        let auth_context = AuthenticationContext::with_time("20220101", "20220101T010203Z");
        println!("{:?}", auth_context.date_time);
        let result = build_authorization_token(&auth_context, "test-signature".to_string());
        unset_test_env();
        let expected = "AWS4-HMAC-SHA256 Credential=test-access-key/20220101/test-region/kms/aws4_request, SignedHeaders=content-length;content-type;host;x-amz-date;x-amz-security-token;x-amz-target, Signature=test-signature";
        assert_eq!(expected, result);
    }

    #[test]
    fn test_build_signature() {
        set_test_env();
        let auth_context = AuthenticationContext::with_time("20220101", "20220101T010203Z");
        let headers = "20220101/test-region/kms/aws4_request".to_string();
        let result = build_signature("test-data", headers, &auth_context);
        unset_test_env();
        assert_eq!("2d00a717685bf2e0b2b3b70f8718d0b9cbe28875da76cb10600b06e88f213b7a", result);
    }

    #[test]
    fn test_build_canonical_string() {
        set_test_env();
        let auth_context = AuthenticationContext::with_time("20220101", "20220101T010203Z");
        let result = build_canonical_string(&auth_context, "test-data");
        unset_test_env();
        assert_eq!("POST\n/\n\ncontent-length:9\ncontent-type:application/x-amz-json-1.1\nhost:kms.test-region.amazonaws.com\nx-amz-date:20220101T010203Z\nx-amz-security-token:test-session-token\nx-amz-target:TrentService.Decrypt\n\ncontent-length;content-type;host;x-amz-date;x-amz-security-token;x-amz-target\na186000422feab857329c684e9fe91412b1a5db084100b37a98cfc95b62aa867", result);
    }

    #[test]
    fn test_build_header_list() {
        set_test_env();
        let auth_context = AuthenticationContext::with_time("20220101", "20220101T010203Z");
        let result = build_header_list(&auth_context, "test-data").unwrap();
        unset_test_env();
        let mut expected = vec![
            "X-Amz-Security-Token: test-session-token",
            "Authorization: AWS4-HMAC-SHA256 Credential=test-access-key/20220101/test-region/kms/aws4_request, SignedHeaders=content-length;content-type;host;x-amz-date;x-amz-security-token;x-amz-target, Signature=2d00a717685bf2e0b2b3b70f8718d0b9cbe28875da76cb10600b06e88f213b7a",
            "X-Amz-Date: 20220101T010203Z",
            "Content-Length: 9",   
            "Content-Type: application/x-amz-json-1.1", 
            "X-Amz-Target: TrentService.Decrypt",    
        ];
        let mut item_count = 0;
        for val in result.iter() {
            item_count += 1;
            assert_eq!(expected.pop().unwrap(), String::from_utf8_lossy(val));    
        }
        assert_eq!(6, item_count);
    }

    #[test]
    fn test_format_response() {
        assert_eq!("{\"blablabla\":true}", format_response(b"{\"blablabla\":true}", true));
    }

    fn set_test_env() {
        std::env::set_var(ENV_REGION, "test-region");
        std::env::set_var(ENV_FUNCTION_NAME, "test-function-name");
        std::env::set_var(ENV_ACCESS_KEY, "test-access-key");
        std::env::set_var(ENV_SECRET_KEY, "test-secret-key");
        std::env::set_var(ENV_SESSION_TOKEN, "test-session-token");
    }

    fn unset_test_env() {
        std::env::remove_var(ENV_REGION);
        std::env::remove_var(ENV_FUNCTION_NAME);
        std::env::remove_var(ENV_ACCESS_KEY);
        std::env::remove_var(ENV_SECRET_KEY);
        std::env::remove_var(ENV_SESSION_TOKEN);

    }
}
