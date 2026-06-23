# vimba-rs

This repository contains safe wrapper functions over raw bindings generated from the Vimba X 2025-3 VmbC API.

This is currently a work in progress.

## Setup

1. Install the Vimba SDK through the website. It should be listed near the bottom for Linux64. As of June 23 2026, it should be named something similar to 'VimbaX_Setup-2026-1-Linux64.tar.gz': https://www.alliedvision.com/en/support/software-downloads/vimba-x-sdk/vimba-x 

2. Unzip the installation tarball into somewhere nice and safe and cd into that directory. cd into the cti directory of the installation: `cd VimbaX_2026-1/cti/` (or whichever path you need to get into the cti dir)

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

5. Find the path to api/lib inside your Vimba installation, and export LD_LIBRARY_PATH as the absolute path to that location: `export LD_LIBRARY_PATH=/opt/VimbaX_2025-3/api/lib`

6. To compile vimba_rs, cd into vimba_rs and run `cargo build`

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