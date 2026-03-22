#![windows_subsystem = "windows"]
//! UnPKd — GUI application using wxDragon (wxWidgets for Rust).

mod pklite;

use std::cell::RefCell;
use std::fs;
use std::path::PathBuf;
use wxdragon::prelude::*;

// ---------------------------------------------------------------------------
// Shared state
// ---------------------------------------------------------------------------
thread_local! {
    static LOADED_FILE: RefCell<Option<(PathBuf, Vec<u8>)>> = RefCell::new(None);
    static DECOMPRESSED: RefCell<Option<Vec<u8>>> = RefCell::new(None);
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn append_log(log_text: TextCtrl, text: &str) {
    let current = log_text.get_value();
    if current.is_empty() {
        log_text.set_value(text);
    } else {
        log_text.set_value(&format!("{}{}", current, text));
    }
}

fn do_open(
    frame: Frame, path_text: TextCtrl, detect_label: StaticText,
    statusbar: StatusBar, log_text: TextCtrl,
) {
    let dialog = FileDialog::builder(&frame)
        .with_message("Open PKLite-compressed DOS executable")
        .with_wildcard("DOS Executables (*.exe;*.com)|*.exe;*.com|All files (*.*)|*.*")
        .with_style(FileDialogStyle::Open | FileDialogStyle::FileMustExist)
        .build();

    if dialog.show_modal() == ID_OK as i32 {
        if let Some(path_str) = dialog.get_path() {
            let path = PathBuf::from(&path_str);
            match fs::read(&path) {
                Ok(data) => {
                    let file_size = data.len();
                    path_text.set_value(&path_str);
                    let status = match pklite::detect_pklite(&data) {
                        Ok(info) => format!("PKLite detected: {}", info),
                        Err(e) => format!("Not PKLite: {}", e),
                    };
                    detect_label.set_label(&status);
                    statusbar.set_status_text(
                        &format!("Loaded: {} ({} bytes)", path_str, file_size), 0,
                    );
                    append_log(log_text, &format!(
                        "--- Opened: {} ({} bytes) ---\n{}\n", path_str, file_size, status,
                    ));
                    LOADED_FILE.with(|f| *f.borrow_mut() = Some((path, data)));
                    DECOMPRESSED.with(|d| *d.borrow_mut() = None);
                }
                Err(e) => {
                    append_log(log_text, &format!("ERROR: Could not read file: {}\n", e));
                    statusbar.set_status_text(&format!("Error: {}", e), 0);
                }
            }
        }
    }
}

fn do_analyze(statusbar: StatusBar, log_text: TextCtrl) {
    LOADED_FILE.with(|f| {
        let borrow = f.borrow();
        if let Some((ref path, ref data)) = *borrow {
            let report = pklite::analyze_pklite(data);
            append_log(log_text, &format!(
                "\n=== Analysis of {} ===\n{}\n", path.display(), report,
            ));
            statusbar.set_status_text("Analysis complete.", 0);
        } else {
            append_log(log_text, "No file loaded. Use Browse to open a file first.\n");
        }
    });
}

fn do_decompress(detect_label: StaticText, statusbar: StatusBar, log_text: TextCtrl) {
    LOADED_FILE.with(|f| {
        let borrow = f.borrow();
        if let Some((ref path, ref data)) = *borrow {
            append_log(log_text, &format!(
                "\n=== Decompressing {} ===\n", path.display(),
            ));
            match pklite::decompress_pklite(data) {
                Ok(result) => {
                    append_log(log_text, &result.log);
                    append_log(log_text, &format!(
                        "SUCCESS: Decompressed to {} bytes.\n", result.original_exe.len(),
                    ));
                    DECOMPRESSED.with(|d| *d.borrow_mut() = Some(result.original_exe));
                    statusbar.set_status_text("Decompression successful! Click Save to write the file.", 0);
                    detect_label.set_label("Decompressed successfully - ready to save.");
                }
                Err(e) => {
                    append_log(log_text, &format!("FAILED: {}\n", e));
                    statusbar.set_status_text(&format!("Decompression failed: {}", e), 0);
                }
            }
        } else {
            append_log(log_text, "No file loaded. Use Browse to open a file first.\n");
        }
    });
}

fn do_save(frame: Frame, statusbar: StatusBar, log_text: TextCtrl) {
    DECOMPRESSED.with(|d| {
        let borrow = d.borrow();
        if let Some(ref decompressed) = *borrow {
            // Build a suggested filename.
            let default_name = LOADED_FILE.with(|f| {
                let b = f.borrow();
                if let Some((ref path, _)) = *b {
                    let stem = path.file_stem()
                        .map(|s| s.to_string_lossy().to_string())
                        .unwrap_or_else(|| "output".to_string());
                    let ext = path.extension()
                        .map(|s| s.to_string_lossy().to_string())
                        .unwrap_or_else(|| "exe".to_string());
                    format!("{}_unpkd.{}", stem, ext)
                } else {
                    "unpkd.exe".to_string()
                }
            });

            let dialog = FileDialog::builder(&frame)
                .with_message("Save decompressed executable")
                .with_wildcard("DOS Executables (*.exe;*.com)|*.exe;*.com|All files (*.*)|*.*")
                .with_style(FileDialogStyle::Save | FileDialogStyle::OverwritePrompt)
                .with_default_file(&default_name)
                .build();

            if dialog.show_modal() == ID_OK as i32 {
                if let Some(save_path) = dialog.get_path() {
                    match fs::write(&save_path, decompressed) {
                        Ok(()) => {
                            append_log(log_text, &format!(
                                "Saved: {} ({} bytes)\n", save_path, decompressed.len(),
                            ));
                            statusbar.set_status_text(&format!("Saved: {}", save_path), 0);
                        }
                        Err(e) => {
                            append_log(log_text, &format!("ERROR saving: {}\n", e));
                            statusbar.set_status_text(&format!("Save error: {}", e), 0);
                        }
                    }
                }
            }
        } else {
            append_log(log_text, "Nothing to save. Decompress a file first.\n");
        }
    });
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

fn main() {
    let _ = wxdragon::main(|_| {
        let frame = Frame::builder()
            .with_title("UnPKd - DOS EXE/COM PKLite Decompressor")
            .with_size(Size::new(720, 560))
            .build();

        // Set window icon (title bar + alt-tab).
        {
            let rgba = include_bytes!("../assets/icon_32x32.rgba");
            if let Some(bmp) = Bitmap::from_rgba(rgba, 32, 32) {
                frame.set_icon(&bmp);
            }
        }

        // === Menus ===
        let id_open: i32 = 1001;
        let id_save: i32 = 1002;
        let id_analyze: i32 = 1003;
        let id_decompress: i32 = 1004;

        let file_menu = Menu::builder().build();
        file_menu.append(id_open, "&Open...\tCtrl+O", "Open a PKLite-compressed file", ItemKind::Normal);
        file_menu.append(id_save, "&Save As...\tCtrl+S", "Save the decompressed file", ItemKind::Normal);
        file_menu.append_separator();
        file_menu.append(ID_EXIT as i32, "E&xit\tAlt+F4", "Quit the application", ItemKind::Normal);

        let tools_menu = Menu::builder().build();
        tools_menu.append(id_analyze, "&Analyze\tCtrl+A", "Analyze the loaded file", ItemKind::Normal);
        tools_menu.append(id_decompress, "&Decompress\tCtrl+D", "Decompress the loaded file", ItemKind::Normal);

        let help_menu = Menu::builder().build();
        help_menu.append(ID_ABOUT as i32, "&About...", "About UnPKd", ItemKind::Normal);

        let menubar = MenuBar::builder().build();
        frame.set_menu_bar(menubar);

        // === Status bar ===
        let statusbar = StatusBar::builder(&frame).build();
        statusbar.set_status_text("Ready - open a PKLite-compressed file to begin.", 0);

        // === Main panel ===
        let panel = Panel::builder(&frame).build();
        let main_sizer = BoxSizer::builder(Orientation::Vertical).build();

        // -----------------------------------------------------------------
        // Row 1: File path + Browse button (wrapped in a Panel for h-layout)
        // -----------------------------------------------------------------
        let file_row = Panel::builder(&panel).build();
        let file_row_sz = BoxSizer::builder(Orientation::Horizontal).build();

        let lbl_file = StaticText::builder(&file_row).with_label(" File:").build();
        file_row_sz.add(&lbl_file, 0, SizerFlag::AlignCenterVertical, 0);

        let path_text = TextCtrl::builder(&file_row)
            .with_style(TextCtrlStyle::ReadOnly)
            .build();
        file_row_sz.add(&path_text, 1, SizerFlag::Expand | SizerFlag::Left | SizerFlag::Right, 6);

        let browse_btn = Button::builder(&file_row).with_label("Browse...").build();
        file_row_sz.add(&browse_btn, 0, SizerFlag::Right, 0);

        file_row.set_sizer(file_row_sz, true);
        main_sizer.add(&file_row, 0, SizerFlag::Expand | SizerFlag::All, 6);

        // -----------------------------------------------------------------
        // Row 2: Detection status label
        // -----------------------------------------------------------------
        let detect_label = StaticText::builder(&panel)
            .with_label("  No file loaded.")
            .build();
        main_sizer.add(
            &detect_label, 0,
            SizerFlag::Expand | SizerFlag::Left | SizerFlag::Right | SizerFlag::Bottom, 6,
        );

        // -----------------------------------------------------------------
        // Row 3: Action buttons (wrapped in a Panel for h-layout)
        // -----------------------------------------------------------------
        let btn_row = Panel::builder(&panel).build();
        let btn_row_sz = BoxSizer::builder(Orientation::Horizontal).build();

        let analyze_btn = Button::builder(&btn_row).with_label("  Analyze  ").build();
        btn_row_sz.add(&analyze_btn, 0, SizerFlag::All, 4);

        let decompress_btn = Button::builder(&btn_row).with_label("  Decompress  ").build();
        btn_row_sz.add(&decompress_btn, 0, SizerFlag::All, 4);

        let save_btn = Button::builder(&btn_row).with_label("  Save As...  ").build();
        btn_row_sz.add(&save_btn, 0, SizerFlag::All, 4);

        let clear_btn = Button::builder(&btn_row).with_label("  Clear Log  ").build();
        btn_row_sz.add(&clear_btn, 0, SizerFlag::All, 4);

        btn_row.set_sizer(btn_row_sz, true);
        main_sizer.add(&btn_row, 0, SizerFlag::Left | SizerFlag::Top | SizerFlag::Bottom, 6);

        // -----------------------------------------------------------------
        // Row 4: Log output (takes remaining space)
        // -----------------------------------------------------------------
        let log_text = TextCtrl::builder(&panel)
            .with_style(TextCtrlStyle::MultiLine | TextCtrlStyle::ReadOnly)
            .build();
        main_sizer.add(&log_text, 1, SizerFlag::Expand | SizerFlag::All, 6);

        panel.set_sizer(main_sizer, true);

        // === Button events ===

        browse_btn.on_click(move |_| {
            do_open(frame, path_text, detect_label, statusbar, log_text);
        });

        analyze_btn.on_click(move |_| {
            do_analyze(statusbar, log_text);
        });

        decompress_btn.on_click(move |_| {
            do_decompress(detect_label, statusbar, log_text);
        });

        save_btn.on_click(move |_| {
            do_save(frame, statusbar, log_text);
        });

        clear_btn.on_click(move |_| {
            log_text.set_value("");
        });

        // === Menu handler (single dispatcher) ===
        frame.on_menu(move |event| {
            let id = event.get_id();
            if id == id_open {
                do_open(frame, path_text, detect_label, statusbar, log_text);
            } else if id == id_save {
                do_save(frame, statusbar, log_text);
            } else if id == ID_EXIT as i32 {
                frame.close(false);
            } else if id == id_analyze {
                do_analyze(statusbar, log_text);
            } else if id == id_decompress {
                do_decompress(detect_label, statusbar, log_text);
            } else if id == ID_ABOUT as i32 {
                MessageDialog::builder(
                    &frame,
                    "UnPKd v0.1.0\n\n\
                     A tool to detect and decompress DOS executables\n\
                     compressed with PKWARE's PKLite utility.\n\n\
                     Built with Rust and wxDragon (wxWidgets).\n\n\
                     Supports PKLite versions 1.00 through 2.01\n\
                     (standard and large compression modes).",
                    "About UnPKd",
                )
                .with_style(MessageDialogStyle::OK | MessageDialogStyle::IconInformation)
                .build()
                .show_modal();
            }
        });

        // === Show ===
        frame.show(true);
        frame.centre();
    });
}
