// use vimba_rs::vimba_rs::api::*;

// fn main() -> Result<(), 


// use vimba_rs::api::*;
// use vimba_rs::ffi::*;
// use std::{mem};

// use std::ffi::c_void;

// this module will contain helper functions to use in the iris_handler
mod vimba_api { 
    // initialize vimba api
    pub fn initialize()  {
        println!("called vimba_api::initialize()");
        match vimba_rs::api::startup(Some("/opt/VimbaX_2025-3/cti/VimbaCameraSimulatorTL.cti")) {
        Ok(()) => {
            println!("Successfully started api");
            
        }
        Err(e) => {
            eprintln!("Failed to start API: {e}");
        }
    }
    }
    // connect to the first camera (list cameras), returns 0 
    pub fn connect_camera() -> vimba_rs::VmbResult<vimba_rs::api::CameraHandle> {
        println!("called vimba_api::connect_camera()");
        let cameras = vimba_rs::api::cameras_list()?;

        println!("Found {} camera(s)", cameras.len());

        //if found == 0, cameras_list returns an empty vector
        let first_camera = cameras.first().ok_or(vimba_rs::VmbError::NotFound)?; // ok_or transforms Some(v) into Ok(v) and None into Err(e), where e is arg to ok or (here is VmbError::NotFound)
        
        println!("{:#?}", first_camera);
        println!("id = {}", first_camera.id);
        println!("extended_id = {}", first_camera.extended_id);
        println!("access = {:?}", first_camera.access);
        /*
        pub struct CameraInfo has the following fields:
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
        */
        println!("First camera found.
            id: {},
            extended_id: {},
            camera_name: {},
            model_name: {},
            serial_number: {},
            transport_layer_handle: {:?},
            interface_handle: {:?},
            local_device_handle: {:?},
            stream_handles: {:?},
            stream_count: {},
            access: {:?}",
            first_camera.id,
            first_camera.extended_id,
            first_camera.camera_name,
            first_camera.model_name,    
            first_camera.serial_number,
            first_camera.transport_layer_handle,
            first_camera.interface_handle,
            first_camera.local_device_handle,
            first_camera.stream_handles,
            first_camera.stream_count,
            first_camera.access,
        );

        // now open and connect to the camera:
        let camera_handle = vimba_rs::api::camera_open(&first_camera.id, vimba_rs::api::AccessMode::Full)?;

        println!("Camera handle: {:?}", camera_handle);

        Ok(camera_handle) //return the camera handle for use in other functions
    }


    unsafe extern "C" fn frame_done_callback(
        camera_handle: *mut std::ffi::c_void,
        _stream_handle: *mut std::ffi::c_void,
        frame: *mut vimba_rs::api::Frame,
    ) {
        println!("############# frame_done_callback");
        if camera_handle.is_null() || frame.is_null() {
            return;
        }

        let camera = unsafe {vimba_rs::api::CameraHandle::from_raw(camera_handle)};
        let frame_ref = unsafe { &mut *frame } ;

        println!(
            "frame received: id={}, width={}, height={}",
            frame_ref.frameID,
            frame_ref.width,
            frame_ref.height
        );

        // Re-queue the same frame for future captures.
        let _ = vimba_rs::api::capture_frame_queue(&camera, frame_ref, Some(frame_done_callback));

        // Prevent accidental drop semantics if you later add Drop.
        std::mem::forget(camera);
    }

    pub fn capture_asynchronous(camera_handle: &vimba_rs::api::CameraHandle, n:u32) -> vimba_rs::VmbResult<()> {
        //prepare image acquisition: 
        // make api aware of buffers using VmbFrameAnnounce
        // start capture engine using VmbCaptureStart
        // hand buffers over to api using VmbCaptureFrameQueue
        println!("########################### CAPTURE ASYNCHRONOUS ###########################");
        
        let payload = vimba_rs::api::payload_size_get(camera_handle)? as usize; //must get size of the payload
        println!("size of payload: {:?}", payload);

        let mut image_buffers = Vec::new(); // empty vector (contiguous growable)
        for ith in 0..n {

            let buffer = vec![0u8; payload];

            image_buffers.push(buffer); // push into image_buffers n image buffers for n frames, each buffer is the size of the payload
            // println!("image buffers at {}th iter: {:?}", ith, image_buffers);
            println!("{}", ith);
        }
        let mut frames = Vec::new();
        for buffer in image_buffers.iter_mut() {
            let frame = vimba_rs::api::frame_from_buffer(buffer);
            frames.push(frame);

            println!("Frame pushed to frames:");
            println!("{:?}", frame);
            
        }
        println!("Frames: {:?}", frames);

        
        //now that we have frames, we need to announce them before we can queue them for capture
        println!("Announcing frames");

        for frame in &frames {
            vimba_rs::api::frame_announce(camera_handle, frame)?;
        }
        println!("Capture start");
        vimba_rs::api::capture_start(camera_handle)?; //calls VmbCaptureStart

        println!("Calling capture_frame_queue");

        // now we can call capture_frame_queue with a callback to be called when the frame is captured
        for frame in &frames {
            // vimba_rs::api::capture_frame_queue(camera_handle, frame, Some(frame_done_callback))?; //register the callback, which must be of type VmbFrameCallback*()
            vimba_rs::api::capture_frame_wait(camera_handle, frame, 2000);
        }
        println!("Running AcquisitionStart");
        //start image acquisition:
        // run camera command feature AcquisitionStart
        vimba_rs::api::feature_command_run(camera_handle, "AcquisitionStart")?;


        //image is within callback function
        // reque frame VmbCaptureframeQueue()

        //stop image acquisiiton:
        // run camera command feature AcquisitionStop
        println!("Running AcquisitionStop");

        vimba_rs::api::feature_command_run(camera_handle, "AcquisitionStop")?;


        //cleanup
        // discard pending frame callbacks, srtop capture engine usign VmbCaptureEnd()
        // flush capture queue using VmbCaptureQueueFlush()
        // revoke all frames using VmbFrameRevokeAll()
        vimba_rs::api::capture_end(camera_handle)?; //stop capturing
        vimba_rs::api::capture_queue_flush(camera_handle)?; //flush the queue
        vimba_rs::api::frame_revoke_all(camera_handle)?; //revoke all frames
        Ok(())
        
    }

    //function to run get and set commands
    pub fn command_run(camera_handle: &vimba_rs::api::CameraHandle, string: &str) -> vimba_rs::VmbResult<bool> {
        println!("Camera handle: {:?}", camera_handle);
        match vimba_rs::api::feature_command_run(camera_handle, string){
            Ok(()) => println!("Successfully ran command {}", string),
            Err(e) => eprintln!("Failed to run command {}: {e}", string),
        }
        // double check if command done using 'feature_command_is_done'
        vimba_rs::api::feature_command_is_done(camera_handle, string)?;
        Ok(true)
    }

    // print out features and their feature info
    //this function is js for debugging, though it should not be used in the actual handler.
    pub fn list_all_features(camera_handle: &vimba_rs::api::CameraHandle) -> vimba_rs::VmbResult<()>{
        match vimba_rs::api::list_features(camera_handle){
            Ok(features) => {
                    // println!("feature count = {}", features.len())
                    for f in &features {
                        println!("#######\nname={}, 
                                category={:?},
                                display_name = {:?},
                                tool_tip = {:?},
                                description = {:?},
                                namespace = {:?},
                                unit = {:?},
                                representation = {:?},
                                data_type = {:?},
                                mode = {:?},
                                flags = {:?},
                                polling_time = {:?},
                                visibility = {:?},
                                is_streamable = {:?},
                                has_selected_features = {:?},
                                write_access = {:?},
                                read_access = {:?},
                                is_volatile = {:?},
                                modify_write = {:?}
                                \n######", 
                                
                                f.name, 
                                f.category,
                                f.display_name,
                                f.tool_tip,
                                f.description,
                                f.namespace,
                                f.unit,
                                f.representation,
                                f.data_type,
                                f.mode,
                                f.flags,
                                f.polling_time,
                                f.visibility,
                                f.is_streamable,
                                f.has_selected_features,
                                // and below we have our flags access booleans:
                                f.flags.write_access(),
                                f.flags.read_access(),
                                f.flags.is_volatile(),
                                f.flags.modify_write());
                    }
                }
            Err(e) => {
                    eprintln!("Failed to list features: {e}");
                }
        }
        Ok(())
    }

    // get feature info and also for now print it out for debugging. important info: datatype (str/bool/enum etc), flags (access,write/read, voltaitle), uhh
    pub fn get_feature_info(
            camera_handle: &vimba_rs::api::CameraHandle,
            feature_str_name: &str,
            ) -> vimba_rs::VmbResult<vimba_rs::api::FeatureInfo> 
    {
        let f = vimba_rs::api::feature_info_query(camera_handle, feature_str_name)?;

        println!(
            "#######\n\
            name = {},\n\
            category = {:?},\n\
            display_name = {:?},\n\
            tool_tip = {:?},\n\
            description = {:?},\n\
            namespace = {:?},\n\
            unit = {:?},\n\
            representation = {:?},\n\
            data_type = {:?},\n\
            flags = {:?},\n\
            polling_time = {:?},\n\
            visibility = {:?},\n\
            is_streamable = {:?},\n\
            has_selected_features = {:?},\n\
            write_access = {:?},\n\
            read_access = {:?},\n\
            is_volatile = {:?},\n\
            modify_write = {:?}\n\
            #######",
            f.name,
            f.category,
            f.display_name,
            f.tool_tip,
            f.description,
            f.namespace,
            f.unit,
            f.representation,
            f.data_type,
            f.flags,
            f.polling_time,
            f.visibility,
            f.is_streamable,
            f.has_selected_features,
            f.flags.write_access(),
            f.flags.read_access(),
            f.flags.is_volatile(),
            f.flags.modify_write(),
        );

        Ok(f)
    }


    // write feature. inputs: feature name, thing to write
    //  first get feature data_type, 
    // then see feature_flags.write_access==true or not, 
    pub fn write_feature(camera_handle: &vimba_rs::api::CameraHandle, feature_str_name: &str, value_to_write: &str) -> vimba_rs::VmbResult<()> {
        match get_feature_info(camera_handle, feature_str_name) {
            Ok(feature_info) =>{
                //now that we have the feature info, simply check whether writable, check data type, etc
                //important note for the user: read and write are self explaantory but 
                // volatile==can change with every read
                // modifywrite == features are adjusted to valid values, 
                    // (so if i write 0.001 to a type that accepts int, i will write 0)
                // TODO shld USER be responsbile for being cautious w volatile cmds
                match feature_info.flags.write_access() {
                    true => {
                        match feature_info.data_type {
                            // given datatype need to either convert value (for instance, need to convert str(x) to int(x) if datatype is x
                            
                            vimba_rs::api::FeatureDataType::Integer =>{
                                println!("Feature data type: {:?}", feature_info.data_type);
                                let value_to_write_converted = value_to_write.parse::<i64>().map_err(|_| vimba_rs::VmbError::BadParameter)?;    
                                //to find out what type to convert to (ie i64) go to the feature_int_set function in src/api.rs and see the typedef for value
                                println!("Converted value: {}", value_to_write_converted);
                                vimba_rs::api::feature_int_set(camera_handle, feature_str_name, value_to_write_converted) //returns VmbResult<()>
                                
                            }
                            vimba_rs::api::FeatureDataType::Float => {
                                println!("Feature data type: {:?}", feature_info.data_type);
                                let value_to_write_converted = value_to_write.parse::<f64>().map_err(|_| vimba_rs::VmbError::BadParameter)?;    
                                println!("Converted value: {}", value_to_write_converted);
                                vimba_rs::api::feature_float_set(camera_handle, feature_str_name, value_to_write_converted)
                            }
                            vimba_rs::api::FeatureDataType::Enum => {
                                println!("Feature data type: {:?}", feature_info.data_type);
                                // value for enum set is &str
                                vimba_rs::api::feature_enum_set(camera_handle, feature_str_name, value_to_write) //returns VmbResult<()>
                            }
                            vimba_rs::api::FeatureDataType::String => {
                                println!("Feature data type: {:?}", feature_info.data_type);
                                vimba_rs::api::feature_string_set(camera_handle, feature_str_name, value_to_write) //returns VmbResult<()>
                            }
                            vimba_rs::api::FeatureDataType::Bool => {
                                let value_to_write_converted = value_to_write.parse::<bool>().map_err(|_| vimba_rs::VmbError::BadParameter)?; 
                                println!("Feature data type: {:?}", feature_info.data_type);
                                println!("Converted value: {}", value_to_write_converted);
                                vimba_rs::api::feature_bool_set(camera_handle, feature_str_name, value_to_write_converted) //returns VmbResult<()>
                            
                            }

                            vimba_rs::api::FeatureDataType::Command => {
                                println!("Feature data type: {:?}", feature_info.data_type);
                                println!("write_feature is not a method for this feature data type.");

                                Err(vimba_rs::VmbError::WrongType)
                            }
                            vimba_rs::api::FeatureDataType::Raw => {
                                println!("Feature data type: {:?}", feature_info.data_type);
                                println!("write_feature is not a method for this feature data type.");
                                Err(vimba_rs::VmbError::WrongType)

                            }
                            vimba_rs::api::FeatureDataType::None=>{
                                println!("Feature data type: {:?}", feature_info.data_type);
                                println!("write_feature is not a method for this feature data type.");
                                Err(vimba_rs::VmbError::WrongType)
                            }
                            vimba_rs::api::FeatureDataType::Unknown =>{
                                println!("Feature data type: {:?}", feature_info.data_type);
                                println!("write_feature is not a method for this feature data type.");
                                Err(vimba_rs::VmbError::WrongType)
                            }
                        }
                    }
                    false => {
                        // if no write access, then return the function with error InvalidAccess
                        Err(vimba_rs::VmbError::InvalidAccess)
                    }
                }
            

            }
            Err(e) => {
                println!("Error getting feature info for {}. Error: {e}", feature_str_name);
                Err(e)
            }
        }
    }

    // NOTE for user!!! input features as 'string1.string2' (with a single period) if enum entry, where string1 is enum and string2 is the enum entry,
        //  and input feature as 'string' where string is either an int, float, bool, string, enum (other types do not have the handling for reading)
    pub fn read_feature(camera_handle: &vimba_rs::api::CameraHandle, feature_str_name: &str) -> vimba_rs::VmbResult<vimba_rs::api::FeatureValue> {
        //if type is EnumEntry, you need to specify the enum AND the enum entry for that enum; in the string, denote this via 'Enum.EnumEntry' 
        if let Some((feature_name, enum_entry_name)) = feature_str_name.split_once('.'){
            //a split occured ==> handle this case as EnumEntry, where in 'string1.string2', string1 is the enum and string2 is the enum entry
            let v = vimba_rs::api::feature_enum_entry_get(camera_handle, feature_name, enum_entry_name)?;
            Ok(vimba_rs::api::FeatureValue::EnumEntry(v))
        }
        else {
            // no split occured, aka try to parse just that string as a feature
            match get_feature_info(camera_handle, feature_str_name) {
            Ok(feature_info) => {
                //check if readable
                // TODO shld USER be responsbile for being cautious w volatile cmds? voltatile ==> can change w every read
                match feature_info.flags.read_access() {
                    true => {
                            match feature_info.data_type {
                                vimba_rs::api::FeatureDataType::Integer => {
                                    let v = vimba_rs::api::feature_int_get(camera_handle, feature_str_name)?;
                                    Ok(vimba_rs::api::FeatureValue::Integer(v))
                                }
                                vimba_rs::api::FeatureDataType::Float => {
                                    let v = vimba_rs::api::feature_float_get(camera_handle, feature_str_name)?;
                                    Ok(vimba_rs::api::FeatureValue::Float(v))
                                }
                                vimba_rs::api::FeatureDataType::Bool => {
                                    let v = vimba_rs::api::feature_bool_get(camera_handle, feature_str_name)?;
                                    Ok(vimba_rs::api::FeatureValue::Bool(v))
                                }
                                vimba_rs::api::FeatureDataType::String => {
                                    let v = vimba_rs::api::feature_string_get(camera_handle, feature_str_name)?;
                                    Ok(vimba_rs::api::FeatureValue::String(v))
                                }
                                vimba_rs::api::FeatureDataType::Enum => {
                                    let v = vimba_rs::api::feature_enum_get(camera_handle, feature_str_name)?;
                                    Ok(vimba_rs::api::FeatureValue::Enum(v))
                                }
                                _ => Err(vimba_rs::VmbError::WrongType), //cannot read 
                                }   
                            }
                    false => {
                        // if no write access, then return the function with error InvalidAccess
                        Err(vimba_rs::VmbError::InvalidAccess)
                        }
                    }
                }

            
            Err(e) => {
                println!("Error getting feature info for {}. Error: {e}", feature_str_name);
                Err(e)
                }
            }
        }
    }


    pub fn shutdown() {
        println!("called vimba_api::shutdown()");
        vimba_rs::api::shutdown();
    }





    //function to 
}

fn main() {
    vimba_api::initialize();
    { 
    
    //this is a new scope so that handles/cameras/etc are dropped before shutdown is called
    
    match vimba_api::connect_camera() {
        Ok(camera_handle) => {
            println!("Successfully connected to camera with handle: {:?}", &camera_handle);
            // match vimba_rs::api::list_features(&camera_handle){ 
            //     Ok(features) => {
            //         // println!("feature count = {}", features.len())
        
            //         for f in &features {
            //             println!("{} {:?} write_access={}", f.name, f.data_type, f.flags.write_access());
            //         }
            //     }
            //     Err(e) => {
            //         eprintln!("Failed to list features: {e}");
            //     }
               
            // }
            
            // match vimba_api::capture_asynchronous(&camera_handle, 1) {
            //     Ok(()) => {
            //         println!("Successfully executed asynchronous capture");
            //     }
            //     Err(e) => {
            //         eprintln!("Failed to execute asynchronous capture: {e}");
            //     }
            // }

            match vimba_api::write_feature(&camera_handle, "StreamSelector", "0"){
                Ok(()) => {

                }
                Err(e) =>{
                    eprintln!("Failed to write feature: {e}");
                }
            }
        }
        Err(e) => {
            eprintln!("Failed to connect to camera: {e}");
        }
    }
    }

    
    vimba_api::shutdown();
}

// fn main() -> Result<(), Box<dyn std::error::Error>> {
//     println!("logging: startup");
//     // before using any functions in the api, you need to initialize the api.
//     match startup(Some("/opt/VimbaX_2025-3/cti/VimbaUSBTL.cti")) {
//         Ok(()) => {
//             println!("Successfully started api")
//         }
//         Err(e) => {
//             eprintln!("Failed to start API: {e}");
//         }
//     }
//     println!("logging: post startup");

//     match cameras_list()
//     let cam_info = cameras_list()?.into_iter().next().expect("no camera");
//     let cam = camera_open(&cam_info.id, AccessMode::Full)?;

//     let payload = payload_size_get(&cam)? as usize;
//     let mut image_buffer = vec![0u8; payload];

//     let mut frame: Frame = unsafe { mem::zeroed() };
//     frame.buffer = image_buffer.as_mut_ptr() as *mut std::ffi::c_void;
//     frame.bufferSize = payload as u32;

//     frame_announce(&cam, &frame)?;
//     capture_start(&cam)?;

//     capture_frame_queue(&cam, &frame, None)?;
//     capture_frame_wait(&cam, &frame, 2000)?;

//     println!("frame received: id={}, width={}, height={}",
//         frame.frameID, frame.width, frame.height);

//     capture_queue_flush(&cam)?;
//     capture_end(&cam)?;
//     frame_revoke(&cam, &frame)?;
//     camera_close(cam)?;
//     shutdown();

//     Ok(())
// }