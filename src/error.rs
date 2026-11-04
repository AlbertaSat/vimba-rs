use crate::ffi::*;
use strum::FromRepr;
use thiserror::Error;

pub type VmbResult<T> = Result<T, VmbError>;

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
    #[error("Incomplete")]
    Incomplete = VmbErrorType_VmbErrorIncomplete,
    #[error("IO")]
    IO = VmbErrorType_VmbErrorIO,
}
