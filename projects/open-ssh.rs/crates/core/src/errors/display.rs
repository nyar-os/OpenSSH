use super::*;
use std::{
    error::Error as StdError,
    fmt::{Display, Formatter},
};

impl StdError for Error {}

impl Display for Error {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self.capability.as_deref() {
            Some(capability) => write!(f, "{} ({capability}): {}", self.code.as_str(), self.message),
            None => write!(f, "{}: {}", self.code.as_str(), self.message),
        }
    }
}

impl Display for CapabilityState {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        Display::fmt(self.code(), f)
    }
}

impl Display for ErrorCode {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        Display::fmt(self.as_str(), f)
    }
}
