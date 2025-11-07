use super::ffi::*;
use std::{mem, ptr};
use strum::FromRepr;
use thiserror::Error;

#[derive(Debug, Copy, Clone)]
pub struct VmbVersion {
    pub major: u32,
    pub minor: u32,
    pub patch: u32,
}

#[repr(i32)]
#[derive(Debug, Copy, Clone, Error, FromRepr)]
pub enum VmbError {
    #[error("Internal VmbC Fault")]
    InternalFault = VmbErrorType_VmbErrorInternalFault,
    #[error("APINotStarted")]
    APINotStarted = VmbErrorType_VmbErrorApiNotStarted,
    #[error("NotFound")]
    NotFound = VmbErrorType_VmbErrorNotFound,
    #[error("BadHandle")]
    BadHandle = VmbErrorType_VmbErrorBadHandle,
    #[error("DeviceNotOpen")]
    DeviceNotOpen = VmbErrorType_VmbErrorDeviceNotOpen,
    #[error("InvalidAccess")]
    InvalidAccess = VmbErrorType_VmbErrorInvalidAccess,
    #[error("BadParameter")]
    BadParameter = VmbErrorType_VmbErrorBadParameter,
    #[error("InvalidStructSize")]
    InvalidStructSize = VmbErrorType_VmbErrorStructSize,
    #[error("MoreData")]
    MoreData = VmbErrorType_VmbErrorMoreData,
    #[error("WrongType")]
    WrongType = VmbErrorType_VmbErrorWrongType,
    #[error("InvalidValue")]
    InvalidValue = VmbErrorType_VmbErrorInvalidValue,
    #[error("Timeout")]
    Timeout = VmbErrorType_VmbErrorTimeout,
    #[error("Other")]
    Other = VmbErrorType_VmbErrorOther,
    #[error("OutOfResource")]
    OutOfResource = VmbErrorType_VmbErrorResources,
    #[error("InvalidCall")]
    InvalidCall = VmbErrorType_VmbErrorInvalidCall,
    #[error("NoTL")]
    NoTL = VmbErrorType_VmbErrorNoTL,
    #[error("NotImplemented")]
    NotImplemented = VmbErrorType_VmbErrorNotImplemented,
    #[error("NotSupported")]
    NotSupported = VmbErrorType_VmbErrorNotSupported,
    #[error("IO")]
    IO = VmbErrorType_VmbErrorIO,
    #[error("ValidValueSetNotPresent")]
    ValidValueSetNotPresent = VmbErrorType_VmbErrorValidValueSetNotPresent,
    #[error("GenTLUnspecified")]
    GenTLUnspecified = VmbErrorType_VmbErrorGenTLUnspecified,
    #[error("Unspecified")]
    Unspecified = VmbErrorType_VmbErrorUnspecified,
    #[error("Busy")]
    Busy = VmbErrorType_VmbErrorBusy,
    #[error("NoData")]
    NoData = VmbErrorType_VmbErrorNoData,
    #[error("ParsingChunkData")]
    ParsingChunkData = VmbErrorType_VmbErrorParsingChunkData,
    #[error("InUse")]
    InUse = VmbErrorType_VmbErrorInUse,
    #[error("Unknown")]
    Unknown = VmbErrorType_VmbErrorUnknown,
    #[error("XML")]
    XML = VmbErrorType_VmbErrorXml,
    #[error("UnAvailable")]
    UnAvailable = VmbErrorType_VmbErrorFeaturesUnavailable,
    #[error("NotInitialized")]
    NotInitialized = VmbErrorType_VmbErrorNotInitialized,
    #[error("InvalidAddress")]
    InvalidAddress = VmbErrorType_VmbErrorInvalidAddress,
    #[error("AlreadyDone")]
    AlreadyDone = VmbErrorType_VmbErrorAlready,
    #[error("NoChunkData")]
    NoChunkData = VmbErrorType_VmbErrorNoChunkData,
    #[error("UserCallBack")]
    UserCallBack = VmbErrorType_VmbErrorUserCallbackException,
    #[error("TLNotFound")]
    TLNotFound = VmbErrorType_VmbErrorTLNotFound,
    #[error("Ambiguous")]
    Ambiguous = VmbErrorType_VmbErrorAmbiguous,
    #[error("RetriesExceeded")]
    RetriesExceeded = VmbErrorType_VmbErrorRetriesExceeded,
    #[error("InsufficientBufferCount")]
    InsufficientBufferCount = VmbErrorType_VmbErrorInsufficientBufferCount,
    #[error("Custom")]
    Custom = VmbErrorType_VmbErrorCustom,
}

pub fn vmb_version_query() -> Result<VmbVersion, VmbError> {
    let mut version_raw = VmbVersionInfo_t {
        major: 0,
        minor: 0,
        patch: 0,
    };

    let err = unsafe {
        let version_raw_mut_ptr = ptr::from_mut(&mut version_raw);
        VmbVersionQuery(
            version_raw_mut_ptr,
            mem::size_of::<VmbVersionInfo_t>() as VmbUint32_t,
        )
    };

    match VmbError::from_repr(err) {
        Some(e) => Err(e),
        None => Ok(VmbVersion {
            major: version_raw.major,
            minor: version_raw.minor,
            patch: version_raw.patch,
        }),
    }
}
