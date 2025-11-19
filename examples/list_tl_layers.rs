use vimba_rs::api::{startup, transport_layers_list,  shutdown};

fn main() {
    match startup(Some("/opt/VimbaX_2025-2/cti/VimbaUSBTL.cti")) {
        Ok(()) => {
            println!("Successfully started api")
        }
        Err(e) => {
            eprintln!("Failed to start API: {e}");
        }
    }

    match transport_layers_list() {
        Ok(list) => {
            println!("Found {} transport layer(s): {:?}", list.len(), list);
        }
        Err(e) => {
            eprintln!("Failed to get transport layer list: {e}");
        }
    }

    println!("Shutting down API");
    shutdown();
}
