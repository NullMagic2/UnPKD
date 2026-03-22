fn main() {
    #[cfg(windows)]
    {
        // Embed the Windows manifest for Common Controls v6 (modern theming).
        // This eliminates the wxWidgets warning about missing manifests.
        use embed_manifest::manifest::{ActiveCodePage, SupportedOS::*};
        use embed_manifest::{embed_manifest, new_manifest};

        let manifest = new_manifest("UnPKd")
            .supported_os(Windows7..=Windows10)
            .active_code_page(ActiveCodePage::Utf8);

        if let Err(e) = embed_manifest(manifest) {
            println!("cargo:warning=Failed to embed manifest: {e}");
        }

        // Embed the application icon into the .exe.
        let mut res = winresource::WindowsResource::new();
        res.set_icon("assets/icon.ico");
        res.set("ProductName", "UnPKd");
        res.set("FileDescription", "PKLite DOS Executable Decompressor");
        if let Err(e) = res.compile() {
            println!("cargo:warning=Failed to embed icon: {e}");
        }
    }

    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=assets/icon.ico");
}
