//! Petits utilitaires sans état : hex, empreintes, exécution bornée.

use sha2::{Digest, Sha256};
use std::io::{Read, Write};
use std::process::{Command, ExitStatus, Stdio};
use std::time::{Duration, Instant};

pub fn hex_encode(bytes: &[u8]) -> String {
    const H: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push(H[(b >> 4) as usize] as char);
        s.push(H[(b & 15) as usize] as char);
    }
    s
}

pub fn hex_decode(s: &str) -> Option<Vec<u8>> {
    if s.is_empty() || !s.len().is_multiple_of(2) || !s.is_ascii() {
        return None;
    }
    s.as_bytes()
        .chunks(2)
        .map(|p| {
            let hi = (p[0] as char).to_digit(16)?;
            let lo = (p[1] as char).to_digit(16)?;
            Some((hi * 16 + lo) as u8)
        })
        .collect()
}

/// Empreinte courte d'un secret (16 hex). Sert à reconnaître « c'est le même
/// login qu'avant » sans jamais écrire le secret nulle part.
pub fn fingerprint(secret: &str) -> String {
    hex_encode(&Sha256::digest(secret.as_bytes())[..8])
}

pub struct ProcOutput {
    /// `None` si le processus a été tué faute de réponse à temps.
    pub status: Option<ExitStatus>,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
}

impl ProcOutput {
    pub fn timed_out(&self) -> bool {
        self.status.is_none()
    }
    pub fn code(&self) -> Option<i32> {
        self.status.and_then(|s| s.code())
    }
    pub fn stdout_str(&self) -> String {
        String::from_utf8_lossy(&self.stdout).into_owned()
    }
    pub fn stderr_str(&self) -> String {
        String::from_utf8_lossy(&self.stderr).into_owned()
    }
}

/// Lance `cmd`, lui envoie `stdin` puis le ferme, et le tue au bout de `timeout`.
/// Pourquoi : `security` peut attendre indéfiniment une fenêtre d'autorisation du
/// Trousseau, et `claude auth status` peut bloquer sur un réseau mort ; aucun des
/// deux ne doit figer l'accueil du wizard.
pub fn run_bounded(
    cmd: &mut Command,
    stdin: Option<&[u8]>,
    timeout: Duration,
) -> std::io::Result<ProcOutput> {
    cmd.stdin(if stdin.is_some() {
        Stdio::piped()
    } else {
        Stdio::null()
    })
    .stdout(Stdio::piped())
    .stderr(Stdio::piped());
    let mut child = cmd.spawn()?;
    if let (Some(data), Some(mut si)) = (stdin, child.stdin.take()) {
        // Un échec d'écriture (processus déjà mort) se lit dans le code de sortie.
        let _ = si.write_all(data);
    }
    let mut so = child.stdout.take();
    let mut se = child.stderr.take();
    let t_out = std::thread::spawn(move || {
        let mut v = Vec::new();
        if let Some(s) = so.as_mut() {
            let _ = s.read_to_end(&mut v);
        }
        v
    });
    let t_err = std::thread::spawn(move || {
        let mut v = Vec::new();
        if let Some(s) = se.as_mut() {
            let _ = s.read_to_end(&mut v);
        }
        v
    });
    let start = Instant::now();
    let status = loop {
        match child.try_wait()? {
            Some(st) => break Some(st),
            None if start.elapsed() >= timeout => {
                let _ = child.kill();
                let _ = child.wait();
                break None;
            }
            None => std::thread::sleep(Duration::from_millis(15)),
        }
    };
    let stdout = t_out.join().unwrap_or_default();
    let stderr = t_err.join().unwrap_or_default();
    Ok(ProcOutput {
        status,
        stdout,
        stderr,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_roundtrip() {
        let b = [0u8, 1, 0xab, 0xff];
        assert_eq!(hex_encode(&b), "0001abff");
        assert_eq!(hex_decode("0001abff").unwrap(), b);
        assert!(hex_decode("0g").is_none());
        assert!(hex_decode("abc").is_none());
        assert!(hex_decode("").is_none());
    }

    #[test]
    fn fingerprint_is_short_and_stable() {
        let f = fingerprint("secret");
        assert_eq!(f.len(), 16);
        assert_eq!(f, fingerprint("secret"));
        assert_ne!(f, fingerprint("secret2"));
    }

    #[cfg(unix)]
    #[test]
    fn run_bounded_captures_and_times_out() {
        let o = run_bounded(
            &mut Command::new("/bin/cat"),
            Some(b"salut"),
            Duration::from_secs(5),
        )
        .unwrap();
        assert_eq!(o.stdout_str(), "salut");
        assert_eq!(o.code(), Some(0));
        let mut c = Command::new("/bin/sleep");
        c.arg("5");
        let o = run_bounded(&mut c, None, Duration::from_millis(100)).unwrap();
        assert!(o.timed_out());
    }
}
