# vimba-rs

This repository contains safe wrapper functions over raw bindings generated from the Vimba X 2025-2 VmbC API.

This is currently a work in progress.

## Setup

Some extra steps are required to run the `query_version` example. Here I will only cover how to set up on linux.

After cloning the repository or adding the crate to you Cargo.toml you must add Vimba's library directory to your LD_LIBRARY_PATH so that the example can link at runtime with the libVmbC.so:

``` Bash
export LD_LIBRARY_PATH=/opt/VimbaX_2025-3/api/lib
```

Now you can run the `query_version` example:

``` Bash
cargo run --example query_version
```

__Note:__ This example can run without being connected to the camera.
