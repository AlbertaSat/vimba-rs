# vimba-rs

This repository contains safe wrapper functions over raw bindings generated from the Vimba (VimbaC) 5.0 API.

Note: this crate targets the older **Vimba 5.0** SDK (`VimbaC.h`), not VimbaX/VmbC. The two have
different C APIs (VimbaX's `VmbC` has transport-layer/local-device/stream handles that Vimba 5.0
does not, a `VmbStartup(pathConfiguration)` vs. Vimba 5.0's no-argument `VmbStartup()`, etc.), so
bindings generated against one are not compatible with code written against the other.

## Setup

1. Install the Vimba 5.0 SDK for Linux64 from Allied Vision and unpack it to `/opt/Vimba_5_0`
   (that absolute path is hard-coded into `wrapper.h` and `build.rs`; if you install elsewhere,
   update both files to match).

2. Register the GenTL transport layer(s) you need so the API can discover cameras. Each transport
   layer under the SDK ships its own install script — for example, for USB cameras:

   ```
   cd /opt/Vimba_5_0/VimbaUSBTL
   sudo ./Install.sh        # registers GENICAM_GENTL64_PATH system-wide (requires a reboot/relogin)
   . ./SetGenTLPath.sh       # or: set GENICAM_GENTL64_PATH for the current shell only
   ```

   Do the same under `VimbaGigETL` if you need GigE camera support. `GENICAM_GENTL64_PATH` is a
   colon-separated list of directories containing `.cti` files, e.g.:

   ```
   export GENICAM_GENTL64_PATH=/opt/Vimba_5_0/VimbaUSBTL/CTI/x86_64bit:/opt/Vimba_5_0/VimbaGigETL/CTI/x86_64bit
   ```

   Unlike VimbaX, Vimba 5.0 has no camera-simulator transport layer — testing without hardware
   attached isn't supported by this SDK.

3. Clone the repository AlbertaSat/vimba_rs.

4. To compile vimba_rs, cd into vimba_rs and run `cargo build`. `build.rs` already points
   `rustc-link-search`/`rustc-link-lib` at `/opt/Vimba_5_0/VimbaC/DynamicLib/x86_64bit` and
   `/opt/Vimba_5_0/VimbaImageTransform/DynamicLib/x86_64bit`, and bakes an `-Wl,-rpath` for those
   same directories into the built binaries — so `LD_LIBRARY_PATH` does not need to be set to run
   binaries built from this crate.

Example:
```
oliveoil@oliveoil-ubuntu:~/Desktop/AlbertaSat/ex3_software/fsw/vendor/vimba_rs$ cargo build
    Finished `dev` profile [unoptimized + debuginfo] target(s) in 0.05s
```

5. To run some Rust program vimba_rs/examples/program.rs, run `cargo run --example program`

Example:
```
(base) oliveoil@oliveoil-ubuntu:~/Desktop/AlbertaSat/ex3_software/fsw/vendor/vimba_rs$ cargo run --example query_version
   Compiling vimba-rs v0.1.0 (/home/oliveoil/Desktop/AlbertaSat/ex3_software/fsw/vendor/vimba_rs)
    Finished `dev` profile [unoptimized + debuginfo] target(s) in 0.15s
     Running `/home/oliveoil/Desktop/AlbertaSat/ex3_software/target/debug/examples/query_version`
VmbVersion { major: 1, minor: 8, patch: 5 }
```

Other examples available under `examples/`: `connect` (find/open the first camera and run an
asynchronous capture) and `list_tl_layers` (list the interfaces currently visible to the API).