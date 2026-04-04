// use vimba_rs::api::*;

// fn main() -> Result<(), 


use vimba_rs::api::*;
// use vimba_rs::ffi::*;
use std::{mem};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("logging: startup");
    // before using any functions in the api, you need to initialize the api.
    match startup(Some("/opt/VimbaX_2025-3/cti/VimbaUSBTL.cti")) {
        Ok(()) => {
            println!("Successfully started api")
        }
        Err(e) => {
            eprintln!("Failed to start API: {e}");
        }
    }
    println!("logging: post startup");


    let cam_info = cameras_list()?.into_iter().next().expect("no camera");
    let cam = camera_open(&cam_info.id, AccessMode::Full)?;

    let payload = payload_size_get(&cam)? as usize;
    let mut image_buffer = vec![0u8; payload];

    let mut frame: Frame = unsafe { mem::zeroed() };
    frame.buffer = image_buffer.as_mut_ptr() as *mut std::ffi::c_void;
    frame.bufferSize = payload as u32;

    frame_announce(&cam, &frame)?;
    capture_start(&cam)?;

    capture_frame_queue(&cam, &frame, None)?;
    capture_frame_wait(&cam, &frame, 2000)?;

    println!("frame received: id={}, width={}, height={}",
        frame.frameID, frame.width, frame.height);

    capture_queue_flush(&cam)?;
    capture_end(&cam)?;
    frame_revoke(&cam, &frame)?;
    camera_close(cam)?;
    shutdown();

    Ok(())
}