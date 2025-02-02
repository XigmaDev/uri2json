use std::fmt;

#[derive(Debug)]
pub enum ConversionError {
    InvalidUri,
    UnsupportedProtocol(String),
    ParseError(String),
    SerializationError(String),
    IoError(String),
    UnsupportedFeature(String),
    InvalidVersion(String),
    MissingPassword,
    MissingHost,
    MissingPort,
    MissingUUID,
    MissingIP,
    MissingPublicKey,
    FailedDecode,
    InvalidVmessFormat,
    InvalidJson,

}

impl fmt::Display for ConversionError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::InvalidUri => write!(f, "Invalid URI format"),
            Self::UnsupportedProtocol(p) => write!(f, "Unsupported protocol: {}", p),
            Self::ParseError(e) => write!(f, "Parse error: {}", e),
            Self::SerializationError(e) => write!(f, "Serialization error: {}", e),
            Self::IoError(e) => write!(f, "IO error: {}", e),
            Self::UnsupportedFeature(e) => write!(f, "Unsupported feature: {}", e),
            Self::InvalidVersion(e) => write!(f, "Invalid version: {}", e),
            Self::MissingPassword => write!(f, "Missing password"),
            Self::MissingHost => write!(f, "Missing host"),
            Self::MissingPort => write!(f, "Missing port"),
            Self::MissingUUID => write!(f, "Missing UUID"),
            Self::MissingIP => write!(f, "Missing IP"),
            Self::MissingPublicKey => write!(f, "Missing public key"),
            Self::FailedDecode => write!(f, "Failed to decode base64"),
            Self::InvalidVmessFormat => write!(f, "Invalid Vmess format"),
            Self::InvalidJson => write!(f, "Invalid JSON"),

        }
    }
}