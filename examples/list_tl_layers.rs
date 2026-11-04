use vimba_rs::api::{interfaces_list, shutdown, startup};

fn main() {
    match startup() {
        Ok(()) => {
            println!("Successfully started api")
        }
        Err(e) => {
            eprintln!("Failed to start API: {e}");
        }
    }

    // Vimba_5_0 has no VmbTransportLayersList; interfaces are the closest
    // enumerable equivalent (e.g. a GigE adapter or the USB bus).
    match interfaces_list() {
        Ok(list) => {
            println!("Found {} interface(s): {:?}", list.len(), list);
        }
        Err(e) => {
            eprintln!("Failed to get interface list: {e}");
        }
    }

    println!("Shutting down API");
    shutdown();
}
