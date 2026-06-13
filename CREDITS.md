# Credits & Acknowledgments

## Rust Rewrite

The Python implementation was fully rewritten in Rust (April 2026) using
**[GitHub Copilot](https://github.com/features/copilot)** powered by **Claude Sonnet 4.6**.
The Rust port produces a single static binary with zero runtime dependencies while
preserving all 90 converter implementations and adding integrated auto-detection.

## Inspiration

This project is directly inspired by the **`*2john` converter scripts** from the
[John the Ripper](https://github.com/openwall/john) project (bleeding-jumbo branch).

The original `*2john` scripts convert various encrypted file formats into John the Ripper's
hash format. **Hashcatizer** adapts these concepts for [hashcat](https://hashcat.net/hashcat/),
outputting hashes in hashcat-compatible format with appropriate mode numbers.

## Original Authors (openwall/john)

The following individuals authored the original JtR converter scripts that served as
reference implementations for Hashcatizer's extraction logic:

- **Dhiru Kholia** (`@kholia`) — `ssh2john.py`, `ethereum2john.py`, `bitcoin2john.py`,
  `ansible2john.py`, `bitwarden2john.py`, `bitlocker2john.py`, `keepass2john.py`,
  `encfs2john.py`, `truecrypt_volume2john.py`, and many others
- **magnumripper** — Core JtR development and hash format contributions
- **Fist0urs** — `office2john.py`, `pdf2john.py` contributions
- **philsmd** — hashcat format specifications and `itunes_backup2hashcat`
- **Chick3nman** — Ethereum hash format design
- **Gavin Andresen** — Original Bitcoin wallet parsing code

## Projects

- **[openwall/john](https://github.com/openwall/john)** — John the Ripper jumbo.
  The `run/` directory contains 80+ converter scripts under permissive licenses.
  Redistribution and use in source and binary forms, with or without modification, are permitted.

- **[hashcat/hashcat](https://github.com/hashcat/hashcat)** — The world's fastest and most
  advanced password recovery utility, created by **Jens "atom" Steube** and the hashcat team.
  Hashcatizer exists to complement hashcat by converting encrypted files into hashcat-ready
  hash format. All mode numbers, hash format specifications, and example hashes referenced in
  this project come from hashcat's excellent documentation. Without hashcat, this project would
  have no purpose. Thank you to the entire hashcat community for building and maintaining such
  an incredible tool.

- **[0x6470/bitwarden2hashcat](https://github.com/0x6470/bitwarden2hashcat)** — Bitwarden
  hash extraction for hashcat.

- **[philsmd/itunes_backup2hashcat](https://github.com/philsmd/itunes_backup2hashcat)** —
  iTunes backup hash extraction.

## License Compatibility

The original JtR Python scripts are released under permissive terms:
> "Redistribution and use in source and binary forms, with or without modification, are permitted."

Hashcatizer is released under the MIT License, which is compatible with this permissive licensing.
