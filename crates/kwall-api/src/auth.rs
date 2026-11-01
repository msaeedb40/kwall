//! API authentication and token verification.

use thiserror::Error;

/// Authentication errors.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum AuthError {
    #[error("Missing Authorization header")]
    MissingHeader,
    #[error("Invalid Authorization header format; expected 'Bearer <token>'")]
    InvalidFormat,
    #[error("Unauthorized: invalid token credentials")]
    InvalidToken,
}

/// Verifies an authorization header value against an expected secret token.
pub fn verify_bearer_token(header: Option<&str>, expected_token: &str) -> Result<(), AuthError> {
    let raw = header.ok_or(AuthError::MissingHeader)?;
    let token = raw
        .strip_prefix("Bearer ")
        .or_else(|| raw.strip_prefix("bearer "))
        .ok_or(AuthError::InvalidFormat)?
        .trim();

    if token == expected_token {
        Ok(())
    } else {
        Err(AuthError::InvalidToken)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_auth_token_verification() {
        let secret = "kwall-super-secret-token";
        assert!(verify_bearer_token(Some("Bearer kwall-super-secret-token"), secret).is_ok());
        assert_eq!(
            verify_bearer_token(Some("Bearer wrong-token"), secret),
            Err(AuthError::InvalidToken)
        );
        assert_eq!(
            verify_bearer_token(Some("Basic 12345"), secret),
            Err(AuthError::InvalidFormat)
        );
        assert_eq!(
            verify_bearer_token(None, secret),
            Err(AuthError::MissingHeader)
        );
    }
}
