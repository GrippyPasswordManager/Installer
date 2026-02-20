# Grippy Installer

A hardened Windows installer for [Grippy](https://github.com/Xoifail), built with Tauri 2 and Rust.

## What it does

- Installs the Grippy desktop app and posture service to `C:\Program Files\Grippy`
- Bootstraps prerequisites (VC++ 2022 Runtime, WebView2) with Authenticode verification
- Creates and starts the `GrippyPosture` Windows service
- Registers an uninstaller in Add/Remove Programs
- Creates desktop and Start Menu shortcuts
- Supports `--uninstall` for clean removal

## Security

The installer runs with administrator privileges and implements several hardening measures:

- **Payload integrity** : Embedded ZIP is SHA-256 verified at both build time and runtime
- **Authenticode verification** : All downloaded prerequisites are verified against Microsoft's certificate chain with full revocation checking
- **Symlink/junction attack prevention** : Every directory is checked for reparse points before extraction
- **Zip bomb guards** : Entry count and extracted size limits prevent decompression attacks
- **CSPRNG temp paths** : Temp files use cryptographically random names to prevent prediction
- **Restricted ACLs** : Log directory and install mutex are locked to Administrators and SYSTEM
- **Transactional rollback** : If any install step fails, all completed steps are rolled back

## License

Copyright (C) 2025 Xoifail

This program is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.

See [LICENSE](LICENSE) for the full text.
