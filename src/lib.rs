//! This library is for logging into a minecraft account using the microsoft oauth2 device flow: https://docs.microsoft.com/en-us/azure/active-directory/develop/v2-oauth2-device-code
//! # Example
//! ```
//! const CID: &str = "client id from an azure application"
//! fn main() {
//!    let client = &reqwest::blocking::Client::new();
//!    let device_code = ms_auth_mc::DeviceCode::new(CID, None, client).unwrap();
//!    
//!    if !device_code.cached {
//!      println!("{}", device_code.message)
//!    }
//!    
//!    let mca = device_code.authenticate(client).unwrap(); // Never use unwrap here, it's used in this example for simplicity
//!    println!("{:?}", mca)
//! }
//! ```

use {
    reqwest::{blocking::Client, StatusCode},
    serde_derive::{Deserialize, Serialize},
    serde_json::json,
    std::{fs, path::Path, string::String},
};

const CACHE_FILE_NAME: &str = "auth.cache";

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Auth {
    pub name: String,
    pub uuid: String,
    pub token: String,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
struct McProfile {
    id: String,
    name: String,
    // unused
    // pub skins: Vec<Skin>,
    // pub capes: Vec<Cape>,
}

/* unused
#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Skin {
    pub id: String,
    pub state: String,
    pub url: String,
    pub variant: String,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Cape {
    pub id: String,
    pub state: String,
    pub url: String,
    pub alias: String,
}
*/

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
struct McAuth {
    pub access_token: String,
    pub expires_in: i64,
    #[serde(skip)]
    pub expires_after: i64,
}

impl McAuth {
    fn mc_profile(&self, client: &Client) -> anyhow::Result<McProfile> {
        let pr_resp = client
            .get("https://api.minecraftservices.com/minecraft/profile")
            .header("Authorization", format!("Bearer {}", self.access_token))
            .send()?;

        let mc_profile = serde_json::from_reader(pr_resp)?;
        Ok(mc_profile)
    }
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
struct DisplayClaims {
    xui: Vec<Xui>,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
struct Xui {
    uhs: String,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct XstsAuth {
    token: String,
    display_claims: DisplayClaims,
}

impl XstsAuth {
    fn auth_mc(&self, client: &Client) -> anyhow::Result<McAuth> {
        let json = json!({
            "identityToken": format!("XBL3.0 x={};{}", self.display_claims.xui[0].uhs, self.token)
        });

        let mc_resp = client
            .post("https://api.minecraftservices.com/authentication/login_with_xbox")
            .header("Accept", "application/json")
            .json(&json)
            .send()?
            .error_for_status()?;

        let mut mc_auth: McAuth = serde_json::from_reader(mc_resp)?;
        mc_auth.expires_after = mc_auth.expires_in + chrono::Utc::now().timestamp();
        Ok(mc_auth)
    }
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct XblAuth {
    token: String,
}

impl XblAuth {
    fn auth_xsts(&self, client: &Client) -> anyhow::Result<XstsAuth> {
        let json = json!({
            "Properties": {
                "SandboxId":  "RETAIL",
                "UserTokens": [self.token]
            },
            "RelyingParty": "rp://api.minecraftservices.com/",
            "TokenType":    "JWT",
        });

        let xsts_resp = client
            .post("https://xsts.auth.xboxlive.com/xsts/authorize")
            .header("Content-Type", "application/json")
            .json(&json)
            .send()?
            .error_for_status()?;

        let xsts_auth: XstsAuth = serde_json::from_reader(xsts_resp)?;

        Ok(xsts_auth)
    }
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
struct MsAuthRefresh {
    // unused
    // token_type: String,
    // user_id: String,
    // scope: String,
    expires_in: i64,
    access_token: String,
    refresh_token: String,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
struct MsAuth {
    // unused
    // pub token_type: String,
    // pub scope: String,
    // pub ext_expires_in: i64,
    expires_in: i64,
    access_token: String,
    refresh_token: String,
    #[serde(skip)]
    expires_after: i64,
}

impl MsAuth {
    /// Checks if the access token is still valid and refreshes it if it isn't.
    pub fn refresh(&mut self, cid: &str, client: &Client) -> anyhow::Result<bool> {
        if self.expires_after <= chrono::Utc::now().timestamp() {
            let resp = client
                .post("https://login.live.com/oauth20_token.srf")
                .form(&[
                    ("client_id", cid),
                    ("refresh_token", &self.refresh_token),
                    ("grant_type", "refresh_token"),
                    (
                        "redirect_uri",
                        "https://login.microsoftonline.com/common/oauth2/nativeclient",
                    ),
                ])
                .send()?
                .error_for_status()?;
            let refresh: MsAuthRefresh = serde_json::from_reader(resp)?;
            self.access_token = refresh.access_token;
            self.refresh_token = refresh.refresh_token;
            self.expires_after = refresh.expires_in + chrono::Utc::now().timestamp();
            return Ok(true);
        }
        Ok(false)
    }

    pub fn auth_xbl(&self, client: &Client) -> anyhow::Result<XblAuth> {
        let json = json!({
            "Properties": {
                "AuthMethod": "RPS",
                "SiteName":   "user.auth.xboxlive.com",
                "RpsTicket":  &(String::from("d=") + &self.access_token) as &str,
            },
            "RelyingParty": "http://auth.xboxlive.com",
            "TokenType":    "JWT",
        });

        let xbl_resp = client
            .post("https://user.auth.xboxlive.com/user/authenticate")
            .header("Accept", "application/json")
            .json(&json)
            .send()?
            .error_for_status()?;
        let xbl_auth: XblAuth = serde_json::from_reader(xbl_resp)?;
        Ok(xbl_auth)
    }
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
struct MsAuthError {
    error: String,
    // unused
    // pub error_description: String,
    // pub error_codes: Vec<i64>,
    // pub timestamp: String,
    // pub trace_id: String,
    // pub correlation_id: String,
    // pub error_uri: String,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DeviceCode {
    pub user_code: String,
    device_code: String,
    pub verification_uri: String,
    expires_in: i64,
    interval: u64,
    pub message: String,
    #[serde(skip)]
    cid: String,
    #[serde(skip)]
    pub cached: bool,
    #[serde(skip)]
    cache: String,
}

impl DeviceCode {
    /// Entry point of the auth flow.
    /// It's up to you how you show the user the user code and the link
    /// Only show the user code and the link when cached is false because they'll be empty if not.
    pub fn new(cid: &str, cache_file: Option<&str>, client: &Client) -> anyhow::Result<Self> {
        let (path, name) = match cache_file {
            Some(file) => (Path::new(file), file),
            None => (Path::new(CACHE_FILE_NAME), CACHE_FILE_NAME),
        };

        let mut device_code: DeviceCode;
        if !path.exists() {
            let device_resp = client
                .get("https://login.microsoftonline.com/consumers/oauth2/v2.0/devicecode")
                .query(&[
                    ("client_id", cid),
                    ("scope", "XboxLive.signin offline_access"),
                ])
                .header("content-length", "0")
                .send()?
                .error_for_status()?;
            device_code = serde_json::from_reader(device_resp)?;
            device_code.cached = true;
        } else {
            device_code = DeviceCode {
                user_code: String::new(),
                device_code: String::new(),
                verification_uri: String::new(),
                expires_in: 0,
                interval: 0,
                message: String::new(),
                cid: String::new(),
                cached: false,
                cache: String::from(name),
            }
        }
        device_code.cid = String::from(cid);

        Ok(device_code)
    }

    fn auth_ms(&self, client: &Client) -> anyhow::Result<Option<MsAuth>> {
        if !self.cached {
            loop {
                std::thread::sleep(std::time::Duration::from_secs(self.interval + 1));

                let code_resp = client
                    .post("https://login.microsoftonline.com/consumers/oauth2/v2.0/token")
                    .form(&[
                        ("client_id", &self.cid as &str),
                        ("scope", "XboxLive.signin offline_access"),
                        ("grant_type", "urn:ietf:params:oauth:grant-type:device_code"),
                        ("device_code", &self.device_code),
                    ])
                    .send()?;
                match code_resp.status() {
                    StatusCode::BAD_REQUEST => {
                        let ms_auth: MsAuthError = serde_json::from_reader(code_resp)?;
                        match &ms_auth.error as &str {
                            "authorization_pending" => continue,
                            "authorization_declined" => {
                                return Err(anyhow::Error::msg(format!("{}", ms_auth.error)))
                            }
                            "expired_token" => {
                                return Err(anyhow::Error::msg(format!("{}", ms_auth.error)))
                            }
                            "invalid_grant" => {
                                return Err(anyhow::Error::msg(format!("{}", ms_auth.error)))
                            }
                            _ => {
                                continue;
                            }
                        }
                    }
                    StatusCode::OK => {
                        let mut ms_auth: MsAuth = serde_json::from_reader(code_resp)?;
                        ms_auth.expires_after = ms_auth.expires_in + chrono::Utc::now().timestamp();
                        return Ok(Some(ms_auth));
                    }
                    _ => {
                        return Err(anyhow::Error::msg(format!(
                            "unexpected response code: {}",
                            code_resp.status().as_str()
                        )))
                    }
                }
            }
        } else {
            Ok(None)
        }
    }

    /// Call this method after creating the device code and having shown the user the code (but only if DeviceCode.cached is false)
    /// It might block for a while if the access token hasn't been cached yet.
    pub fn authenticate(&self, client: &Client) -> anyhow::Result<Auth> {
        let path: &Path = Path::new(&self.cache);

        let msa = match path.exists() {
            false => {
                let msa = self.auth_ms(client)?;
                fs::write(path, serde_json::ser::to_string(&msa)?)?;
                match msa {
                    Some(x) => x,
                    None => return Err(anyhow::Error::msg("Cache file doesn't exist but Msauth returned None which can only happen if a cache file exists"))
                }
            }
            true => {
                let mut msa: MsAuth = serde_json::from_str(&fs::read_to_string(path)? as &str)?;
                if msa.refresh(&self.cid, client)? {
                    fs::write(path, serde_json::ser::to_string(&msa)?)?;
                }
                msa
            }
        };
        let mca = msa.auth_xbl(client)?.auth_xsts(client)?.auth_mc(client)?;

        let profile = mca.mc_profile(client)?;

        let auth = Auth {
            name: profile.name,
            uuid: profile.id,
            token: mca.access_token,
        };

        Ok(auth)
    }
}
