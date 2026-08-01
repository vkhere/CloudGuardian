"""
tools/make_certs.py
===================
Generates a self-signed WILDCARD certificate so the console can be served over
HTTPS instead of HTTP.

AN IMPORTANT POINT ABOUT WILDCARD CERTIFICATES
    A public certificate authority will only issue a wildcard certificate for a
    domain you provably own (you must satisfy a DNS challenge). You cannot get
    a publicly-trusted certificate for "localhost" or for a private hostname.

    So there are exactly two honest options:

      1. LOCAL (what this script does)
         Issue your own wildcard certificate for a private domain such as
         *.cloudguardian.local, then trust it on your own machine. The browser
         shows a real padlock, traffic is genuinely TLS-encrypted, and the
         certificate is valid for every subdomain you invent. It is trusted
         only on machines where you install the certificate - which is exactly
         right for a lab.

      2. PUBLIC (only if you own a domain)
         Host the console on Azure and bind a certificate for a domain you own.
         App Service offers a free managed certificate for a custom domain, or
         you can upload your own wildcard. See the setup guide, HTTPS chapter.

WHAT THIS PRODUCES
    certs/cloudguardian.crt   the certificate  (safe to share/trust)
    certs/cloudguardian.key   the private key  (never share, never commit)

The certificate covers:
    *.cloudguardian.local, cloudguardian.local, localhost, 127.0.0.1, ::1

USAGE
    python tools/make_certs.py
    python tools/make_certs.py --domain mylab.local --days 825
"""

from __future__ import annotations

import argparse
import datetime
import ipaddress
import os
import sys

try:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
except ImportError:
    print("The 'cryptography' package is required.\n"
          "Install it with:  python -m pip install cryptography")
    sys.exit(1)


def build_cert(domain: str, days: int, out_dir: str) -> tuple[str, str]:
    print(f"Generating a 2048-bit RSA key...")
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "IN"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "CloudGuardian Lab"),
        x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "Capstone"),
        x509.NameAttribute(NameOID.COMMON_NAME, f"*.{domain}"),
    ])

    # Subject Alternative Names. Modern browsers ignore CN entirely and read
    # only this extension, so the wildcard MUST appear here.
    sans = [
        x509.DNSName(f"*.{domain}"),
        x509.DNSName(domain),
        x509.DNSName("localhost"),
        x509.IPAddress(ipaddress.IPv4Address("127.0.0.1")),
        x509.IPAddress(ipaddress.IPv6Address("::1")),
    ]

    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(now + datetime.timedelta(days=days))
        .add_extension(x509.SubjectAlternativeName(sans), critical=False)
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True, key_encipherment=True, key_cert_sign=True,
                content_commitment=False, data_encipherment=False,
                key_agreement=False, crl_sign=False,
                encipher_only=False, decipher_only=False,
            ), critical=True)
        .add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
        .sign(key, hashes.SHA256())
    )

    os.makedirs(out_dir, exist_ok=True)
    crt_path = os.path.join(out_dir, "cloudguardian.crt")
    key_path = os.path.join(out_dir, "cloudguardian.key")

    with open(crt_path, "wb") as fh:
        fh.write(cert.public_bytes(serialization.Encoding.PEM))
    with open(key_path, "wb") as fh:
        fh.write(key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        ))

    # Restrict the key where the OS supports it.
    try:
        os.chmod(key_path, 0o600)
    except OSError:
        pass

    return crt_path, key_path


def main() -> int:
    ap = argparse.ArgumentParser(description="Create a self-signed wildcard certificate")
    ap.add_argument("--domain", default="cloudguardian.local",
                    help="Private domain to issue for (default: cloudguardian.local)")
    ap.add_argument("--days", type=int, default=825,
                    help="Validity in days (default 825, the browser maximum)")
    ap.add_argument("--out", default="certs", help="Output directory")
    args = ap.parse_args()

    crt, key = build_cert(args.domain, args.days, args.out)

    print(f"\nCertificate : {crt}")
    print(f"Private key : {key}")
    print(f"Valid for   : *.{args.domain}, {args.domain}, localhost, 127.0.0.1")
    print(f"Expires     : {args.days} days from now")
    print("\nNext steps")
    print("  1. Trust the certificate (PowerShell as Administrator):")
    print(f'     Import-Certificate -FilePath "{crt}" '
          '-CertStoreLocation Cert:\\LocalMachine\\Root')
    print("  2. Add a hosts entry (PowerShell as Administrator):")
    print(f'     Add-Content C:\\Windows\\System32\\drivers\\etc\\hosts '
          f'"127.0.0.1  console.{args.domain}"')
    print("  3. Start the console over HTTPS:")
    print("     .\\run_https.ps1")
    print(f"  4. Browse to: https://console.{args.domain}:8501")
    print("\nNever commit certs/cloudguardian.key to Git — .gitignore already excludes it.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
