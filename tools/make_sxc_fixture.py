#!/usr/bin/env python3
"""Build a StarOffice .sxc fixture (Blowfish CFB, as pre-ODF releases wrote)."""
import base64, os, sys, zipfile

out = sys.argv[1] if len(sys.argv) > 1 else "test.sxc"
cksum = base64.b64encode(os.urandom(20)).decode()
iv = base64.b64encode(os.urandom(8)).decode()
salt = base64.b64encode(os.urandom(16)).decode()

manifest = (
    '<?xml version="1.0" encoding="UTF-8"?>\n'
    '<manifest:manifest xmlns:manifest="http://openoffice.org/2001/manifest">\n'
    ' <manifest:file-entry manifest:media-type="text/xml" manifest:full-path="content.xml">\n'
    '  <manifest:encryption-data manifest:checksum-type="SHA1/1K" manifest:checksum="%s">\n'
    '   <manifest:algorithm manifest:algorithm-name="Blowfish CFB" '
    'manifest:initialisation-vector="%s"/>\n'
    '   <manifest:key-derivation manifest:key-derivation-name="PBKDF2" '
    'manifest:iteration-count="1024" manifest:salt="%s"/>\n'
    '  </manifest:encryption-data>\n'
    ' </manifest:file-entry>\n'
    '</manifest:manifest>\n' % (cksum, iv, salt)
)

with zipfile.ZipFile(out, "w") as z:
    z.writestr("META-INF/manifest.xml", manifest, zipfile.ZIP_DEFLATED)
    z.writestr("content.xml", os.urandom(2048), zipfile.ZIP_STORED)
