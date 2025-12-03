use super::{error::*, ffi::*, utils::*};
use std::{
    ffi::{self, CStr, CString},
    mem::{self, MaybeUninit},
    ptr,
};
use strum::FromRepr;

#[derive(Debug, Copy, Clone)]
pub struct VmbVersion {
    pub major: u32,
    pub minor: u32,
    pub patch: u32,
}

#[repr(transparent)]
#[derive(Debug, Clone)]
pub struct TransportLayerHandle {
    ptr: VmbHandle_t,
}

impl TransportLayerHandle {
    pub unsafe fn from_raw(ptr: VmbHandle_t) -> Self {
        Self { ptr }
    }
    pub fn as_raw(&self) -> VmbHandle_t {
        self.ptr
    }
}

#[repr(transparent)]
#[derive(Debug, Clone)]
pub struct InterfaceHandle {
    ptr: VmbHandle_t,
}

impl InterfaceHandle {
    pub unsafe fn from_raw(ptr: VmbHandle_t) -> Self {
        Self { ptr }
    }
    pub fn as_raw(&self) -> VmbHandle_t {
        self.ptr
    }
}

#[repr(transparent)]
#[derive(Debug, Clone)]
pub struct LocalDeviceHandle {
    ptr: VmbHandle_t,
}

impl LocalDeviceHandle {
    pub unsafe fn from_raw(ptr: VmbHandle_t) -> Self {
        Self { ptr }
    }
    pub fn as_raw(&self) -> VmbHandle_t {
        self.ptr
    }
}

#[repr(transparent)]
#[derive(Debug, Clone)]
pub struct StreamHandles {
    ptr: *const VmbHandle_t,
}

impl StreamHandles {
    pub unsafe fn from_raw(ptr: *const VmbHandle_t) -> Self {
        Self { ptr }
    }
    pub fn as_raw(&self) -> *const VmbHandle_t {
        self.ptr
    }
}

#[repr(transparent)]
#[derive(Debug, Clone)]
pub struct CameraHandle {
    ptr: VmbHandle_t,
}

impl CameraHandle {
    pub unsafe fn from_raw(ptr: VmbHandle_t) -> Self {
        Self { ptr }
    }
    pub fn as_raw(&self) -> VmbHandle_t {
        self.ptr
    }
}

pub fn vmb_version_query() -> VmbResult<VmbVersion> {
    let mut version_raw = VmbVersionInfo_t {
        major: 0,
        minor: 0,
        patch: 0,
    };

    vmb_result(unsafe {
        let version_raw_mut_ptr = ptr::from_mut(&mut version_raw);
        VmbVersionQuery(
            version_raw_mut_ptr,
            mem::size_of::<VmbVersionInfo_t>() as VmbUint32_t,
        )
    })?;

    Ok(VmbVersion {
        major: version_raw.major,
        minor: version_raw.minor,
        patch: version_raw.patch,
    })
}

pub fn startup(path_config: Option<&str>) -> VmbResult<()> {
    let path = path_config.unwrap_or("/opt/VimbaX-2025_2/cti/VimbaUSBTL.cti");

    let path = ffi::CString::new(path).unwrap();
    vmb_result(unsafe { VmbStartup(path.as_ptr()) })?;
    Ok(())
}

pub fn shutdown() {
    unsafe {
        VmbShutdown();
    }
}

#[repr(u32)]
#[derive(Debug, Clone, Copy, FromRepr)]
pub enum TransportLayerType {
    Unknown = VmbTransportLayerType_VmbTransportLayerTypeUnknown,
    GEV = VmbTransportLayerType_VmbTransportLayerTypeGEV,
    CameraLink = VmbTransportLayerType_VmbTransportLayerTypeCL,
    IIDC = VmbTransportLayerType_VmbTransportLayerTypeIIDC,
    UVC = VmbTransportLayerType_VmbTransportLayerTypeUVC,
    CXP = VmbTransportLayerType_VmbTransportLayerTypeCXP,
    CameraLinkHS = VmbTransportLayerType_VmbTransportLayerTypeCLHS,
    U3V = VmbTransportLayerType_VmbTransportLayerTypeU3V,
    Ethernet = VmbTransportLayerType_VmbTransportLayerTypeEthernet,
    PCI = VmbTransportLayerType_VmbTransportLayerTypePCI,
    Custom = VmbTransportLayerType_VmbTransportLayerTypeCustom,
    Mixed = VmbTransportLayerType_VmbTransportLayerTypeMixed,
}

#[derive(Debug, Clone)]
pub struct TransportLayerInfo {
    pub id: String,
    pub name: String,
    pub model_name: String,
    pub vendor: String,
    pub path: String,
    pub tl_type: TransportLayerType,
    pub handle: TransportLayerHandle,
}

pub fn transport_layers_list() -> VmbResult<Vec<TransportLayerInfo>> {
    let mut found = 0 as VmbUint32_t;
    let tl_info_size = mem::size_of::<VmbTransportLayerInfo_t>() as VmbUint32_t;

    vmb_result(unsafe {
        VmbTransportLayersList(ptr::null_mut(), 0 as ffi::c_uint, &mut found, tl_info_size)
    })?;

    if found == 0 {
        return Ok(Vec::new());
    }

    let mut layers_raw: Vec<mem::MaybeUninit<VmbTransportLayerInfo_t>> =
        vec![mem::MaybeUninit::uninit(); found as usize];

    vmb_result(unsafe {
        VmbTransportLayersList(
            layers_raw.as_mut_ptr().cast(),
            found,
            &mut found,
            tl_info_size,
        )
    })?;

    fn convert_tl_info_safe(
        layer: mem::MaybeUninit<VmbTransportLayerInfo_t>,
    ) -> Result<TransportLayerInfo, VmbError> {
        let layer = unsafe { layer.assume_init() };

        Ok(TransportLayerInfo {
            id: string_from_raw(layer.transportLayerIdString)
                .map_err(|_| VmbError::InternalFault)?,
            name: string_from_raw(layer.transportLayerName).map_err(|_| VmbError::InternalFault)?,
            model_name: string_from_raw(layer.transportLayerModelName)
                .map_err(|_| VmbError::InternalFault)?,
            vendor: string_from_raw(layer.transportLayerVendor)
                .map_err(|_| VmbError::InternalFault)?,
            path: string_from_raw(layer.transportLayerPath).map_err(|_| VmbError::InternalFault)?,
            tl_type: TransportLayerType::from_repr(layer.transportLayerType)
                .ok_or(VmbError::InternalFault)?,
            handle: unsafe { TransportLayerHandle::from_raw(layer.transportLayerHandle) },
        })
    }

    layers_raw
        .iter()
        .map(|layer| convert_tl_info_safe(*layer))
        .collect::<VmbResult<Vec<TransportLayerInfo>>>()
}

pub struct InterfaceInfo {
    pub id: String,
    pub name: String,
    pub interface_handle: InterfaceHandle,
    pub transport_layer_handle: TransportLayerHandle,
    pub interface_type: TransportLayerType,
}

pub fn interfaces_list() -> VmbResult<Vec<InterfaceInfo>> {
    let mut found = 0 as VmbUint32_t;
    let info_size = mem::size_of::<VmbInterfaceInfo_t>() as VmbUint32_t;

    vmb_result(unsafe {
        VmbInterfacesList(ptr::null_mut(), 0 as ffi::c_uint, &mut found, info_size)
    })?;

    if found == 0 {
        return Ok(Vec::new());
    }

    let mut interfaces_raw: Vec<mem::MaybeUninit<VmbInterfaceInfo_t>> =
        vec![mem::MaybeUninit::uninit(); found as usize];

    vmb_result(unsafe {
        VmbInterfacesList(
            interfaces_raw.as_mut_ptr().cast(),
            found,
            &mut found,
            info_size,
        )
    })?;

    fn convert_interface_info_safe(
        interface: mem::MaybeUninit<VmbInterfaceInfo_t>,
    ) -> VmbResult<InterfaceInfo> {
        let interface = unsafe { interface.assume_init() };

        Ok(InterfaceInfo {
            id: string_from_raw(interface.interfaceIdString)
                .map_err(|_| VmbError::InternalFault)?,
            name: string_from_raw(interface.interfaceName).map_err(|_| VmbError::InternalFault)?,
            interface_type: TransportLayerType::from_repr(interface.interfaceType)
                .ok_or(VmbError::InternalFault)?,
            interface_handle: unsafe { InterfaceHandle::from_raw(interface.interfaceHandle) },
            transport_layer_handle: unsafe {
                TransportLayerHandle::from_raw(interface.transportLayerHandle)
            },
        })
    }

    interfaces_raw
        .iter()
        .map(|interface| convert_interface_info_safe(*interface))
        .collect::<VmbResult<Vec<InterfaceInfo>>>()
}

#[derive(Debug, Clone)]
pub struct CameraInfo {
    pub id: String,
    pub extended_id: String,
    pub camera_name: String,
    pub model_name: String,
    pub serial_number: String,
    pub transport_layer_handle: TransportLayerHandle,
    pub interface_handle: InterfaceHandle,
    pub local_device_handle: LocalDeviceHandle,
    pub stream_handles: StreamHandles,
    pub stream_count: u32,
    pub access: AccessMode,
}

#[repr(u32)]
#[derive(Debug, Copy, Clone, FromRepr)]
pub enum AccessMode {
    None = VmbAccessModeType_VmbAccessModeNone,
    Full = VmbAccessModeType_VmbAccessModeFull,
    Read = VmbAccessModeType_VmbAccessModeRead,
    Unknown = VmbAccessModeType_VmbAccessModeUnknown,
    Exclusive = VmbAccessModeType_VmbAccessModeExclusive,
}

pub fn cameras_list() -> VmbResult<Vec<CameraInfo>> {
    let mut found = 0 as VmbUint32_t;
    let info_size = mem::size_of::<VmbCameraInfo_t>() as VmbUint32_t;

    vmb_result(unsafe {
        VmbCamerasList(ptr::null_mut(), 0 as ffi::c_uint, &mut found, info_size)
    })?;

    if found == 0 {
        return Ok(Vec::new());
    }

    let mut cameras_raw: Vec<mem::MaybeUninit<VmbCameraInfo_t>> =
        vec![mem::MaybeUninit::uninit(); found as usize];

    vmb_result(unsafe {
        VmbCamerasList(
            cameras_raw.as_mut_ptr().cast(),
            found,
            &mut found,
            info_size,
        )
    })?;

    cameras_raw
        .iter()
        .map(|camera| convert_camera_info_safe(*camera))
        .collect::<VmbResult<Vec<CameraInfo>>>()
}

pub fn camera_info_query_by_handle(handle: LocalDeviceHandle) -> VmbResult<CameraInfo> {
    let mut camera_info_raw: MaybeUninit<VmbCameraInfo_t> = MaybeUninit::uninit();
    let info_size = size_of::<VmbCameraInfo_t>() as u32;

    vmb_result(unsafe {
        VmbCameraInfoQueryByHandle(handle.as_raw(), camera_info_raw.as_mut_ptr(), info_size)
    })?;

    convert_camera_info_safe(camera_info_raw)
}

fn convert_camera_info_safe(camera: mem::MaybeUninit<VmbCameraInfo_t>) -> VmbResult<CameraInfo> {
    let camera = unsafe { camera.assume_init() };

    Ok(CameraInfo {
        id: string_from_raw(camera.cameraIdString).map_err(|_| VmbError::InternalFault)?,
        extended_id: string_from_raw(camera.cameraIdExtended)
            .map_err(|_| VmbError::InternalFault)?,
        camera_name: string_from_raw(camera.cameraName).map_err(|_| VmbError::InternalFault)?,
        model_name: string_from_raw(camera.modelName).map_err(|_| VmbError::InternalFault)?,
        serial_number: string_from_raw(camera.serialString).map_err(|_| VmbError::InternalFault)?,
        transport_layer_handle: unsafe {
            TransportLayerHandle::from_raw(camera.transportLayerHandle)
        },
        interface_handle: unsafe { InterfaceHandle::from_raw(camera.interfaceHandle) },
        local_device_handle: unsafe { LocalDeviceHandle::from_raw(camera.localDeviceHandle) },
        stream_handles: unsafe { StreamHandles::from_raw(camera.streamHandles) },
        stream_count: camera.streamCount,
        access: AccessMode::from_repr(camera.permittedAccess).ok_or(VmbError::InternalFault)?,
    })
}

pub fn camera_info_query(camera_id: &str) -> VmbResult<CameraInfo> {
    let mut camera_info_raw: MaybeUninit<VmbCameraInfo_t> = MaybeUninit::uninit();
    let info_size = size_of::<VmbCameraInfo_t>() as u32;

    vmb_result(unsafe {
        VmbCameraInfoQuery(
            camera_id.as_ptr().cast(),
            camera_info_raw.as_mut_ptr(),
            info_size,
        )
    })?;

    convert_camera_info_safe(camera_info_raw)
}

pub fn camera_open(id: &str, mode: AccessMode) -> VmbResult<CameraHandle> {
    let mut camera_handle_raw: MaybeUninit<VmbHandle_t> = MaybeUninit::uninit();

    vmb_result(unsafe {
        VmbCameraOpen(
            id.as_ptr().cast(),
            mode as VmbUint32_t,
            camera_handle_raw.as_mut_ptr(),
        )
    })?;

    let camera_handle = unsafe {
        let camera_handle_raw = camera_handle_raw.assume_init();
        CameraHandle::from_raw(camera_handle_raw)
    };

    Ok(camera_handle)
}

pub fn camera_close(handle: CameraHandle) -> VmbResult<()> {
    vmb_result(unsafe { VmbCameraClose(handle.as_raw()) })?;
    Ok(())
}

pub struct FeatureInfo {
    pub name: String,
    pub category: String,
    pub display_name: String,
    pub tool_tip: String,
    pub description: String,
    pub namespace: String,
    pub unit: String,
    pub representation: String,
    pub data_type: FeatureDataType,
    pub flags: FeatureFlags,
    pub polling_time: u32,
    pub visibility: FeatureVisibility,
    pub is_streamable: bool,
    pub has_selected_features: bool,
}

#[repr(u32)]
#[derive(Debug, Clone, Copy, FromRepr)]
pub enum FeatureDataType {
    Unknown = VmbFeatureDataType_VmbFeatureDataUnknown,
    Integer = VmbFeatureDataType_VmbFeatureDataInt,
    Float = VmbFeatureDataType_VmbFeatureDataFloat,
    Enum = VmbFeatureDataType_VmbFeatureDataEnum,
    String = VmbFeatureDataType_VmbFeatureDataString,
    Bool = VmbFeatureDataType_VmbFeatureDataBool,
    Command = VmbFeatureDataType_VmbFeatureDataCommand,
    Raw = VmbFeatureDataType_VmbFeatureDataRaw,
    None = VmbFeatureDataType_VmbFeatureDataNone,
}

#[repr(u32)]
#[derive(Debug, Clone, Copy, FromRepr)]
pub enum FeatureVisibility {
    Unknown = VmbFeatureVisibilityType_VmbFeatureVisibilityUnknown,
    Beginner = VmbFeatureVisibilityType_VmbFeatureVisibilityBeginner,
    Expert = VmbFeatureVisibilityType_VmbFeatureVisibilityExpert,
    Guru = VmbFeatureVisibilityType_VmbFeatureVisibilityGuru,
    Invisible = VmbFeatureVisibilityType_VmbFeatureVisibilityInvisible,
}

#[repr(u32)]
#[derive(Debug, Clone, Copy, FromRepr)]
pub enum FeatureFlags {
    None = VmbFeatureFlagsType_VmbFeatureFlagsNone,
    Read = VmbFeatureFlagsType_VmbFeatureFlagsRead,
    Write = VmbFeatureFlagsType_VmbFeatureFlagsWrite,
    Volatile = VmbFeatureFlagsType_VmbFeatureFlagsVolatile,
    ModifyWrite = VmbFeatureFlagsType_VmbFeatureFlagsModifyWrite,
}

pub fn list_features(handle: &CameraHandle) -> VmbResult<Vec<FeatureInfo>> {
    let mut found = 0 as VmbUint32_t;
    let info_size = mem::size_of::<VmbFeatureInfo_t>() as VmbUint32_t;

    vmb_result(unsafe {
        VmbFeaturesList(
            handle.as_raw(),
            ptr::null_mut(),
            0 as ffi::c_uint,
            &mut found,
            info_size,
        )
    })?;

    if found == 0 {
        return Ok(Vec::new());
    }

    fn convert_feature_info_safe(
        camera: mem::MaybeUninit<VmbFeatureInfo_t>,
    ) -> VmbResult<FeatureInfo> {
        let feature = unsafe { camera.assume_init() };

        Ok(FeatureInfo {
            name: string_from_raw(feature.name).map_err(|_| VmbError::InternalFault)?,
            category: string_from_raw(feature.category).map_err(|_| VmbError::InternalFault)?,
            display_name: string_from_raw(feature.displayName)
                .map_err(|_| VmbError::InternalFault)?,
            tool_tip: string_from_raw(feature.tooltip).map_err(|_| VmbError::InternalFault)?,
            description: string_from_raw(feature.description)
                .map_err(|_| VmbError::InternalFault)?,
            namespace: string_from_raw(feature.sfncNamespace)
                .map_err(|_| VmbError::InternalFault)?,
            unit: string_from_raw(feature.unit).map_err(|_| VmbError::InternalFault)?,
            representation: string_from_raw(feature.representation)
                .map_err(|_| VmbError::InternalFault)?,
            data_type: FeatureDataType::from_repr(feature.featureDataType)
                .ok_or(VmbError::InternalFault)?,
            flags: FeatureFlags::from_repr(feature.featureFlags).ok_or(VmbError::InternalFault)?,
            polling_time: feature.pollingTime,
            visibility: FeatureVisibility::from_repr(feature.visibility)
                .ok_or(VmbError::InternalFault)?,
            is_streamable: feature.isStreamable & 0x01 == 1,
            has_selected_features: feature.hasSelectedFeatures & 0x01 == 1,
        })
    }

    let mut features_raw: Vec<mem::MaybeUninit<VmbFeatureInfo_t>> =
        vec![mem::MaybeUninit::uninit(); found as usize];

    vmb_result(unsafe {
        VmbFeaturesList(
            handle.as_raw(),
            features_raw.as_mut_ptr().cast(),
            found,
            &mut found,
            info_size,
        )
    })?;

    features_raw
        .iter()
        .map(|feature| convert_feature_info_safe(*feature))
        .collect::<VmbResult<Vec<FeatureInfo>>>()
}

// pub fn feature_info_query() 

// pub fn feature_access_query()

// pub fn list_feature_selected()

pub fn feature_int_get(handle: &CameraHandle, name: &str) -> VmbResult<Vec<FeatureInfo>> {
    let feature_name = CString::new(name).map_err(|_| VmbError::BadParameter)?;
    let mut value = 0 as VmbInt64_t;

    vmb_result(unsafe {
        VmbFeatureIntGet(
            handle.as_raw(),
            feature_name.as_ptr(),
            &mut value,
        )
    })?;

    Ok(value)
}

pub fn feature_int_set(handle: &CameraHandle, name: &str, value: i64) -> VmbResult<()> {
    let value = value as VmbInt64_t;
    let feature_name = CString::new(name).map_err(|_| VmbError::BadParameter)?;

    vmb_result(unsafe {
        VmbFeatureIntSet(
            handle.as_raw(),
            feature_name.as_ptr(),
            value,
        )
    })?;

    Ok(())
}

// pub fn feature_int_range_query()

// pub fn feature_int_increment_query()

// pub fn feature_int_valid_value_set_query()

pub fn feature_float_get(handle: &CameraHandle, name: &str) -> VmbResult<Vec<FeatureInfo>> {
    let feature_name = CString::new(name).map_err(|_| VmbError::BadHandle)?;
    let mut value: f64 = 0;

    vmb_result( unsafe {
        VmbFeatureFloatGet(
            handle.as_raw(),
            feature_name.as_ptr(),
            &value,
        )
    })?;

    Ok(value)
}

pub fn feature_float_set(handle: &CameraHandle, name: &str, value: f64) -> VmbResult<()> {
    let feature_name=  CString::new(name).map_err(|_| VmbError::BadHandle)?;

    vmb_result( unsafe {
        VmbFeatureFloatSet(
            handle.as_raw(),
            feature_name.as_ptr(),
            &value,
        )
    })?;

    Ok(())
}

// pub fn feature_float_range_query()

pub fn feature_enum_get(handle: &CameraHandle, name: &str) -> VmbResult<Vec<FeatureInfo>> {
    let feature_name = CString::new(name).map_err(|_| VmbError::BadHandle)?;
    let mut value: *const std::os::raw::c_char = std::ptr::null();

    vmb_result( unsafe {
        VmbFeatureEnumGet(
            handle.as_raw(),
            feature_name.as_ptr(),
            &mut value,
        )
    })?;

    if value.is_null() {
        return Err(VmbError::BadParameter)
    }

    let value = unsafe { CStr::from_ptr(value) }.to_string_lossy().into_owned();

    Ok(value)
}

// pub fn feature_enum_set()

// pub fn feature_enum_range_query()

// pub fn feature_enum_is_available()

// pub fn feature_enum_as_int()

// pub fn feature_enum_as_string()

// pub fn feature_enum_entry_get()

// pub fn feature_string_get()

// pub fn feature_string_set()

// pub fn feature_string_max_length_query()

pub fn feature_bool_get(handle: &CameraHandle, name: &str) -> VmbResult<Vec<FeatureInfo>> {
    let feature_name = CString::new(name).map_err(|_| VmbError::BadHandle)?;
    let mut value = False as VmbBool_t;

    vmb_result( unsafe {
        VmbFeatureBoolGet(
            handle.as_raw(),
            feature_name.as_ptr(),
            &mut value,
        )
    })?;

    Ok(value)
}

pub fn feature_bool_set(handle: &CameraHandle, name: &str, value: bool) -> VmbResult<()> {
    let feature_name = CString::new(name).map_err(|_| VmbError::BadHandle)?;
    let feature_value = match value {
        true => VmbBoolTrue,
        false => VmbBoolFalse,
    };

    vmb_result( unsafe {
        VmbFeatureBoolSet(
            handle.as_raw(),
            feature_name.as_ptr(),
            &value,
        )
    })?;

    Ok(())
}

// pub fn feature_command_run()

// pub fn feature_command_is_done()

// pub fn feature_raw_get()

// pub fn feature_raw_set()

// pub fn feature_raw_length_query()

// pub fn feature_invalidation_register()

// pub fn feature_invalidation_unregister()

// pub fn frame_announce()

// pub fn frame_revoke()

// pub fn frame_revoke_all()

// pub fn capture_start()

// pub fn capture_end()

// pub fn capture_frame_queue()

// pub fn capture_frame_wait()

// pub fn capture_queue_flush()

// pub fn memory_read()

// pub fn memory_write()

// pub fn registers_read()

// pub fn registers_write()

// pub fn camera_settings_save()

// pub fn camera_settings_load()

// pub fn chunk_data_access()