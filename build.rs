fn main() {
    #[cfg(feature = "vergen")]
    if let Err(e) =
        vergen::EmitBuilder::builder()
        .all_build()
        .all_cargo()
        .all_git()
        .all_rustc()
        .all_sysinfo()
        .emit()
    {
        println!("cargo::warning=unable to obtain 'vergen build info': {e:?}");
    }
}

