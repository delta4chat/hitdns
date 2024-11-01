fn main() {
    #[cfg(feature = "rsinfo")]
    rsinfo::build!();

    #[cfg(feature = "doh3")]
    println!("cargo::rustc-cfg=reqwest_unstable");
}

