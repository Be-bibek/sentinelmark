//! Configuration module — loads and validates all environment variables.
//! Fails fast on invalid production configuration.

use std::env;

#[derive(Debug, Clone)]
pub struct Config {
    pub port: u16,
    pub database_url: String,
    pub rust_log: String,
    pub auth_mode: AuthMode,
    pub jwt_secret: Option<String>,
    pub cors_allowed_origins: Vec<String>,
    pub environment: Environment,
}

#[derive(Debug, Clone, PartialEq)]
pub enum AuthMode {
    Disabled,
    Jwt,
    ApiKey,
}

#[derive(Debug, Clone, PartialEq)]
pub enum Environment {
    Development,
    Production,
}

impl Config {
    pub fn from_env() -> Result<Self, ConfigError> {
        // Load .env file if present (ignored in production where env is set externally)
        let _ = dotenvy::dotenv();

        let port = env::var("PORT")
            .unwrap_or_else(|_| "8080".to_string())
            .parse::<u16>()
            .map_err(|_| {
                ConfigError::InvalidValue("PORT must be a valid port number".to_string())
            })?;

        let database_url = env::var("DATABASE_URL")
            .map_err(|_| ConfigError::Missing("DATABASE_URL".to_string()))?;

        let rust_log = env::var("RUST_LOG").unwrap_or_else(|_| "info".to_string());

        let auth_mode = match env::var("AUTH_MODE")
            .unwrap_or_else(|_| "disabled".to_string())
            .to_lowercase()
            .as_str()
        {
            "jwt" => AuthMode::Jwt,
            "apikey" => AuthMode::ApiKey,
            _ => AuthMode::Disabled,
        };

        let jwt_secret = env::var("JWT_SECRET").ok();

        // In production, JWT mode requires a secret
        let environment = match env::var("ENVIRONMENT")
            .unwrap_or_else(|_| "development".to_string())
            .to_lowercase()
            .as_str()
        {
            "production" => Environment::Production,
            _ => Environment::Development,
        };

        if environment == Environment::Production
            && auth_mode == AuthMode::Jwt
            && jwt_secret.is_none()
        {
            return Err(ConfigError::InvalidValue(
                "JWT_SECRET is required when AUTH_MODE=jwt in production".to_string(),
            ));
        }

        let cors_origins_raw = env::var("CORS_ALLOWED_ORIGINS")
            .unwrap_or_else(|_| "http://localhost:3000,http://localhost:3001".to_string());
        let cors_allowed_origins = cors_origins_raw
            .split(',')
            .map(|s| s.trim().to_string())
            .collect();

        Ok(Config {
            port,
            database_url,
            rust_log,
            auth_mode,
            jwt_secret,
            cors_allowed_origins,
            environment,
        })
    }

    pub fn is_production(&self) -> bool {
        self.environment == Environment::Production
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("Missing required environment variable: {0}")]
    Missing(String),
    #[error("Invalid configuration value: {0}")]
    InvalidValue(String),
}
