//! PuTTY `.ppk` private keys (format 2 and 3) converted in memory to an OpenSSH private key,
//! because libssh2 only understands OpenSSH / PEM keys. The decrypted key is never written to disk.
//!
//! Format reference: PuTTY manual, appendix C ("PPK file format").

use base64::{engine::general_purpose::STANDARD as B64, Engine};
use hmac::{Hmac, Mac};
use sha1::Sha1;
use sha2::{Digest, Sha256};

type R<T> = Result<T, String>;

pub fn is_ppk(text: &str) -> bool {
    text.trim_start().starts_with("PuTTY-User-Key-File-")
}

struct Ppk {
    version: u8,
    alg: String,
    encryption: String,
    comment: String,
    public: Vec<u8>,
    private: Vec<u8>,
    mac: String,
    argon: Option<(String, u32, u32, u32, Vec<u8>)>, // variant, memory KiB, passes, parallelism, salt
}

fn parse(text: &str) -> R<Ppk> {
    let mut lines = text.lines().map(str::trim_end);
    let first = lines.next().unwrap_or_default();
    let (ver, alg) = first
        .strip_prefix("PuTTY-User-Key-File-")
        .and_then(|r| r.split_once(": "))
        .ok_or("Not a PuTTY key file")?;
    let version: u8 = ver.parse().map_err(|_| "Unknown PPK version")?;
    if version != 2 && version != 3 {
        return Err(format!("PPK version {version} is not supported"));
    }
    let mut p = Ppk {
        version,
        alg: alg.to_string(),
        encryption: String::new(),
        comment: String::new(),
        public: vec![],
        private: vec![],
        mac: String::new(),
        argon: None,
    };
    let (mut variant, mut mem, mut passes, mut par, mut salt) = (String::new(), 0, 0, 0, vec![]);
    while let Some(line) = lines.next() {
        let Some((k, v)) = line.split_once(": ") else { continue };
        let mut block = |n: &str| -> R<Vec<u8>> {
            let n: usize = n.parse().map_err(|_| "Bad line count")?;
            let b64: String = (0..n).filter_map(|_| lines.next()).collect();
            B64.decode(b64).map_err(|e| format!("Bad base64 in PPK: {e}"))
        };
        match k {
            "Encryption" => p.encryption = v.to_string(),
            "Comment" => p.comment = v.to_string(),
            "Public-Lines" => p.public = block(v)?,
            "Private-Lines" => p.private = block(v)?,
            "Private-MAC" => p.mac = v.to_ascii_lowercase(),
            "Key-Derivation" => variant = v.to_string(),
            "Argon2-Memory" => mem = v.parse().unwrap_or(0),
            "Argon2-Passes" => passes = v.parse().unwrap_or(0),
            "Argon2-Parallelism" => par = v.parse().unwrap_or(0),
            "Argon2-Salt" => salt = hex(v)?,
            _ => {}
        }
    }
    if !variant.is_empty() {
        p.argon = Some((variant, mem, passes, par, salt));
    }
    Ok(p)
}

fn hex(s: &str) -> R<Vec<u8>> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(s.get(i..i + 2).ok_or("Bad hex")?, 16).map_err(|_| "Bad hex".to_string()))
        .collect()
}

fn to_hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn put_string(out: &mut Vec<u8>, s: &[u8]) {
    out.extend_from_slice(&(s.len() as u32).to_be_bytes());
    out.extend_from_slice(s);
}

/// Reads SSH wire-format strings/mpints from a blob.
struct Wire<'a>(&'a [u8]);
impl<'a> Wire<'a> {
    fn string(&mut self) -> R<&'a [u8]> {
        let len = u32::from_be_bytes(self.0.get(..4).ok_or("Truncated key")?.try_into().unwrap()) as usize;
        let s = self.0.get(4..4 + len).ok_or("Truncated key")?;
        self.0 = &self.0[4 + len..];
        Ok(s)
    }
}

fn aes256_cbc_decrypt(key: &[u8], iv: &[u8], data: &mut [u8]) -> R<()> {
    use aes::cipher::{block_padding::NoPadding, BlockDecryptMut, KeyIvInit};
    cbc::Decryptor::<aes::Aes256>::new_from_slices(key, iv)
        .map_err(|e| e.to_string())?
        .decrypt_padded_mut::<NoPadding>(data)
        .map(|_| ())
        .map_err(|_| "Encrypted key has an invalid length".to_string())
}

/// Decrypts and verifies the private blob. Errors mention "passphrase" when one is needed or wrong.
fn decrypt(p: &Ppk, passphrase: &str) -> R<Vec<u8>> {
    let encrypted = match p.encryption.as_str() {
        "none" => false,
        "aes256-cbc" => true,
        other => return Err(format!("PPK encryption '{other}' is not supported")),
    };
    if encrypted && passphrase.is_empty() {
        return Err("This PuTTY key is protected: key passphrase required".into());
    }
    let pass = if encrypted { passphrase.as_bytes() } else { b"" };
    let mut private = p.private.clone();

    let mut mac_data = Vec::new();
    for part in [p.alg.as_bytes(), p.encryption.as_bytes(), p.comment.as_bytes(), &p.public] {
        put_string(&mut mac_data, part);
    }

    let computed = if p.version == 2 {
        if encrypted {
            let mut key = Vec::new();
            for n in [0u32, 1] {
                let mut h = Sha1::new();
                h.update(n.to_be_bytes());
                h.update(pass);
                key.extend_from_slice(&h.finalize());
            }
            aes256_cbc_decrypt(&key[..32], &[0u8; 16], &mut private)?;
        }
        let mut h = Sha1::new();
        h.update(b"putty-private-key-file-mac-key");
        h.update(pass);
        let mac_key = h.finalize();
        put_string(&mut mac_data, &private);
        let mut mac = Hmac::<Sha1>::new_from_slice(&mac_key).unwrap();
        mac.update(&mac_data);
        to_hex(&mac.finalize().into_bytes())
    } else {
        let mut mac_key = vec![];
        if encrypted {
            let (variant, mem, passes, par, salt) = p.argon.as_ref().ok_or("PPK3 key without Key-Derivation")?;
            let alg = match variant.as_str() {
                "Argon2id" => argon2::Algorithm::Argon2id,
                "Argon2i" => argon2::Algorithm::Argon2i,
                "Argon2d" => argon2::Algorithm::Argon2d,
                v => return Err(format!("Key derivation {v} is not supported")),
            };
            let params = argon2::Params::new(*mem, *passes, *par, Some(80)).map_err(|e| e.to_string())?;
            let mut out = [0u8; 80];
            argon2::Argon2::new(alg, argon2::Version::V0x13, params)
                .hash_password_into(pass, salt, &mut out)
                .map_err(|e| e.to_string())?;
            aes256_cbc_decrypt(&out[..32], &out[32..48], &mut private)?;
            mac_key = out[48..80].to_vec();
        }
        put_string(&mut mac_data, &private);
        let mut mac = Hmac::<Sha256>::new_from_slice(&mac_key).unwrap();
        mac.update(&mac_data);
        to_hex(&mac.finalize().into_bytes())
    };
    if computed != p.mac {
        return Err(if encrypted {
            "Wrong passphrase for this PuTTY key".into()
        } else {
            "PuTTY key file is corrupted (MAC mismatch)".into()
        });
    }
    Ok(private)
}

/// Converts PPK text to an unencrypted "-----BEGIN OPENSSH PRIVATE KEY-----" string.
pub fn to_openssh(text: &str, passphrase: &str) -> R<String> {
    let p = parse(text)?;
    let private = decrypt(&p, passphrase)?;
    let (mut pubw, mut privw) = (Wire(&p.public), Wire(&private));
    let key_type = pubw.string()?;

    let mut sec = Vec::new();
    let check = 0x4475_636Bu32.to_be_bytes();
    sec.extend_from_slice(&check);
    sec.extend_from_slice(&check);
    put_string(&mut sec, key_type);
    match p.alg.as_str() {
        "ssh-rsa" => {
            let (e, n) = (pubw.string()?, pubw.string()?);
            let (d, pp, q, iqmp) = (privw.string()?, privw.string()?, privw.string()?, privw.string()?);
            for x in [n, e, d, iqmp, pp, q] {
                put_string(&mut sec, x);
            }
        }
        "ssh-ed25519" => {
            let pk = pubw.string()?;
            // The private field is the 32-byte seed (tolerate an mpint-style leading zero).
            let raw = privw.string()?;
            let mut k = if raw.len() == 33 && raw[0] == 0 { raw[1..].to_vec() } else { raw.to_vec() };
            if k.len() > 32 {
                return Err("Invalid Ed25519 key".into());
            }
            while k.len() < 32 {
                k.insert(0, 0);
            }
            put_string(&mut sec, pk);
            let mut both = k;
            both.extend_from_slice(pk);
            put_string(&mut sec, &both);
        }
        a if a.starts_with("ecdsa-sha2-") => {
            let (curve, q) = (pubw.string()?, pubw.string()?);
            put_string(&mut sec, curve);
            put_string(&mut sec, q);
            put_string(&mut sec, privw.string()?);
        }
        other => return Err(format!("PuTTY key type {other} is not supported")),
    }
    put_string(&mut sec, p.comment.as_bytes());
    let mut pad = 1u8;
    while sec.len() % 8 != 0 {
        sec.push(pad);
        pad += 1;
    }

    let mut blob = b"openssh-key-v1\0".to_vec();
    put_string(&mut blob, b"none");
    put_string(&mut blob, b"none");
    put_string(&mut blob, b"");
    blob.extend_from_slice(&1u32.to_be_bytes());
    put_string(&mut blob, &p.public);
    put_string(&mut blob, &sec);

    let b64 = B64.encode(blob);
    let mut out = String::from("-----BEGIN OPENSSH PRIVATE KEY-----\n");
    for chunk in b64.as_bytes().chunks(70) {
        out.push_str(std::str::from_utf8(chunk).unwrap());
        out.push('\n');
    }
    out.push_str("-----END OPENSSH PRIVATE KEY-----\n");
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// KURIR_PPK_DIR=<dir with *.ppk and a `pass` file> cargo test ppk::tests::convert_dir -- --ignored
    /// Writes <name>.openssh next to each key so it can be checked with `ssh-keygen -y`.
    #[test]
    #[ignore]
    fn convert_dir() {
        let Ok(dir) = std::env::var("KURIR_PPK_DIR") else { return };
        let dir = std::path::Path::new(&dir);
        let pass = std::fs::read_to_string(dir.join("pass")).unwrap();
        let mut n = 0;
        for e in std::fs::read_dir(dir).unwrap() {
            let p = e.unwrap().path();
            if p.extension().is_none_or(|x| x != "ppk") {
                continue;
            }
            let text = std::fs::read_to_string(&p).unwrap();
            let enc = p.to_string_lossy().contains("-enc");
            if enc {
                assert!(to_openssh(&text, "").unwrap_err().contains("passphrase required"), "{p:?}");
                assert!(to_openssh(&text, "wrong").unwrap_err().contains("Wrong passphrase"), "{p:?}");
            }
            let pem = to_openssh(&text, if enc { &pass } else { "" }).unwrap_or_else(|e| panic!("{p:?}: {e}"));
            std::fs::write(p.with_extension("openssh"), pem).unwrap();
            n += 1;
        }
        assert_eq!(n, 16);
    }

    #[test]
    fn rejects_tampered_file() {
        let bad = "PuTTY-User-Key-File-2: ssh-ed25519\nEncryption: none\nComment: x\nPublic-Lines: 1\nAAAAC3NzaC1lZDI1NTE5AAAAIBQ1XqQ8hpL4Wv8T0XN1p9e5d4H2vZc1T1Z6b8u3Xq9a\nPrivate-Lines: 1\nAAAAIQCx\nPrivate-MAC: 00\n";
        assert!(to_openssh(bad, "").is_err());
        assert!(is_ppk(bad) && !is_ppk("-----BEGIN OPENSSH PRIVATE KEY-----"));
    }
}
