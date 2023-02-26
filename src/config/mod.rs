use serde::Deserialize;
use envconfig::Envconfig;

#[derive(Debug, Deserialize, Clone, Envconfig)]
pub struct Config {
    #[envconfig(from = "HOST")]
    pub host: String,
    #[envconfig(from = "PORT")]
    pub port: i32,
    #[envconfig(from = "DATABASE_URL")]
    pub database_url: String,
    #[envconfig(from = "JWT_SECRET_OTP")]
    pub jwt_secret_otp: String,
    #[envconfig(from = "JWT_SECRET_BASIC")]
    pub jwt_secret_basic: String,
    #[envconfig(from = "HASH_SECRET")]
    pub hash_secret: String,
    #[envconfig(from = "SECRET_OTP_ENCRYPTED")]
    pub secret_otp_encrypted: String,
    #[envconfig(from = "SESSION_DURATION")]
    pub session_duration: String,
    #[envconfig(from = "OTP_DURATION")]
    pub otp_duration: String
}

impl Config {
    pub fn from_env() -> Result<Config, String> {

        let config_res = Config::init_from_env();

        match config_res {
            Ok(res) => {
                let web_api_config: Config = res;
                Ok(web_api_config)
            }
            Err(err) => Result::Err(err.to_string())
        }
    }
}