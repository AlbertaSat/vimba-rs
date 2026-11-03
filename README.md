# vimba-rs

This repository contains safe wrapper functions over raw bindings generated from the Vimba X 2025-3 VmbC API.


## Setup

1. Install the Vimba SDK through the website. It should be listed near the bottom for Linux64. As of June 23 2026, it should be named something similar to 'VimbaX_Setup-2026-1-Linux64.tar.gz': https://www.alliedvision.com/en/support/software-downloads/vimba-x-sdk/vimba-x 

2. Unzip the installation tarball into somewhere nice and safe and cd into that directory. cd into the cti directory of the installation: `cd /opt/VimbaX_2025-3/cti/` (or whichever path you need to get into the cti dir)

3. Run the following bash scripts with current working directory in the cti dir: `sudo ./Install_GenTL_Path.sh; . Set_GenTL_Path.sh`

*Example with VimbaX_2025-3:*
```
(base) oliveoil@oliveoil-ubuntu:/opt/VimbaX_2025-3/cti$ sudo ./Install_GenTL_Path.sh 
Registering GENICAM_GENTL64_PATH for Vimba X
Registering AVTUSBTL device types
Done
Please reboot before using the Transport Layers
(base) oliveoil@oliveoil-ubuntu:/opt/VimbaX_2025-3/cti$ . Set_GenTL_Path.sh 

Setting the GENICAM_GENTL64_PATH to /opt/VimbaX_2025-3/cti for this shell only.
  Done
```

4. Clone the repository AlbertaSat/vimba_rs

5. Find the path to api/lib inside your Vimba installation, and export LD_LIBRARY_PATH as the absolute path to that location: `export LD_LIBRARY_PATH=/opt/VimbaX_2025-3/api/lib:/opt/VimbaX_2025-3/bin`

6. To compile vimba_rs, cd into vimba_rs and run `cargo build`

Set `VIMBA_SDK_DIR` at compile time to the Vimba 5 SDK root containing `VimbaC` and `VimbaImageTransform` (default: `/opt/Vimba_5_0`). The library architecture is selected from the Rust target; optionally override it with `VIMBA_LIB_ARCH` (`x86_32bit`, `x86_64bit`, `arm_32bit`, or `arm_64bit`). These build settings use the Vimba 5 directory layout rather than the Vimba X layout shown above.

ARM32 example (requires the Rust target and a configured cross linker):
```sh
VIMBA_SDK_DIR=/path/to/Vimba_5_0 cargo build --target armv7-unknown-linux-gnueabihf
```

Example:
```
oliveoil@oliveoil-ubuntu:~/Desktop/AlbertaSat/ex3_software/fsw/vendor/vimba_rs$ cargo build
    Finished `dev` profile [unoptimized + debuginfo] target(s) in 0.05s
```

7. To run some Rust program vimba_rs/examples/program.rs, run `cargo run --example program`

Example:
```
(base) oliveoil@oliveoil-ubuntu:~/Desktop/AlbertaSat/ex3_software/fsw/vendor/vimba_rs$ cargo run --example query_version
   Compiling vimba-rs v0.1.0 (/home/oliveoil/Desktop/AlbertaSat/ex3_software/fsw/vendor/vimba_rs)
    Finished `dev` profile [unoptimized + debuginfo] target(s) in 0.15s
     Running `/home/oliveoil/Desktop/AlbertaSat/ex3_software/target/debug/examples/query_version`
VmbVersion { major: 1, minor: 2, patch: 0 }
```
