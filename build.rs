use std::env;
use std::path::PathBuf;

fn main() {
    println!("cargo:rerun-if-env-changed=VIMBA_SDK_DIR");
    println!("cargo:rerun-if-env-changed=VIMBA_LIB_ARCH");
    println!("cargo:rerun-if-changed=wrapper.h");

    let sdk_dir =
        PathBuf::from(env::var_os("VIMBA_SDK_DIR").unwrap_or_else(|| "/opt/Vimba_5_0".into()));
    let sdk_dir = sdk_dir.canonicalize().unwrap_or_else(|err| {
        panic!(
            "Cannot access Vimba SDK at {}: {err}. Set VIMBA_SDK_DIR to the SDK root.",
            sdk_dir.display()
        )
    });
    let arch = env::var("VIMBA_LIB_ARCH").unwrap_or_else(|_| {
        match env::var("CARGO_CFG_TARGET_ARCH").unwrap().as_str() {
            "x86" => "x86_32bit",
            "x86_64" => "x86_64bit",
            "arm" => "arm_32bit",
            "aarch64" => "arm_64bit",
            other => panic!("Unsupported Vimba target architecture {other}; set VIMBA_LIB_ARCH"),
        }
        .to_owned()
    });
    let c_lib = sdk_dir.join("VimbaC/DynamicLib").join(&arch);
    let transform_lib = sdk_dir.join("VimbaImageTransform/DynamicLib").join(&arch);
    for (dir, library) in [
        (&c_lib, "libVimbaC.so"),
        (&transform_lib, "libVimbaImageTransform.so"),
    ] {
        assert!(
            dir.join(library).is_file(),
            "Missing {}. Check VIMBA_SDK_DIR and VIMBA_LIB_ARCH.",
            dir.join(library).display()
        );
        println!("cargo:rustc-link-search=native={}", dir.display());
    }
    println!("cargo:rustc-link-lib=VimbaC");
    println!("cargo:rustc-link-lib=VimbaImageTransform");
    println!(
        "cargo:rustc-link-arg=-Wl,-rpath,{}:{}",
        c_lib.display(),
        transform_lib.display()
    );

    let bindings = bindgen::Builder::default()
        // The input header we would like to generate
        // bindings for.
        .header("wrapper.h")
        .clang_arg(format!("-I{}", sdk_dir.join("VimbaC/Include").display()))
        .clang_arg(format!(
            "-I{}",
            sdk_dir.join("VimbaImageTransform/Include").display()
        ))
        // Tell cargo to invalidate the built crate whenever any of the
        // included header files changed.
        .parse_callbacks(Box::new(bindgen::CargoCallbacks::new()))
        // Finish the builder and generate the bindings.
        .generate()
        // Unwrap the Result and panic on failure.
        .expect("Unable to generate bindings");

    // Write the bindings to the $OUT_DIR/bindings.rs file.
    let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());
    bindings
        .write_to_file(out_path.join("bindings.rs"))
        .expect("Couldn't write bindings!");
}
