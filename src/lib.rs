#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "linux")]
use linux as osutils;

use std::path::PathBuf;

use anyhow::anyhow;

pub enum StoreFlavor {
    System,
    NSS,
    Java,
}

/// Installs certs in the platform store. Cert is not checked for validity.
pub fn install_platform(
    flavor: StoreFlavor,
    cert_filename: &'static str,
    cert: Vec<u8>,
) -> Result<(), anyhow::Error> {
    match flavor {
        StoreFlavor::System => Ok(osutils::install_platform(cert_filename, cert)?),
        StoreFlavor::NSS => Ok(nss::install_nss(cert_filename, cert)?),
        _ => Err(anyhow!("Unsupported flavor")),
    }
}

/// Uninstalls certs from the platform store. Cert is not checked for validity.
pub fn uninstall_platform(
    flavor: StoreFlavor,
    cert_filename: &'static str,
) -> Result<(), anyhow::Error> {
    match flavor {
        StoreFlavor::System => Ok(osutils::uninstall_platform(cert_filename)?),
        _ => Err(anyhow!("Unsupported flavor")),
    }
}

#[allow(dead_code)]
/// Returns the home dir of the user + the FIREFOX_SUBDIR variable appended to it. Can be
/// rooted at `/`.
fn firefox_profile() -> Result<String, anyhow::Error> {
    Ok(dirs::home_dir()
        .unwrap_or(PathBuf::from("/"))
        .join(PathBuf::from(osutils::FIREFOX_SUBDIR))
        .to_string_lossy()
        .to_string())
}

mod nss;

#[cfg(test)]
mod tests {
    #[test]
    fn test_firefox_profile() {
        use super::osutils::FIREFOX_SUBDIR;

        let homedir = dirs::home_dir().unwrap();
        let profile_dir = super::firefox_profile().unwrap();
        assert_ne!(profile_dir, "");
        assert!(profile_dir.starts_with(homedir.to_str().unwrap()));
        assert!(profile_dir.ends_with(FIREFOX_SUBDIR));
    }

    //#[cfg(feature = "integration")]
    mod integration {
        use std::{
            io::Read,
            io::Write,
            net::{TcpListener, TcpStream},
            process::Stdio,
            sync::{mpsc, Arc},
            thread,
        };

        use openssl::ssl::{SslAcceptor, SslConnector, SslFiletype, SslMethod};
        use tempdir::TempDir;

        fn make_cert() -> TempDir {
            use std::process::Command;

            let tempdir = TempDir::new("truststore-rs-").unwrap();
            let path = tempdir.path();
            let mut cmd = Command::new("bash");
            let command = cmd.arg("-c").
            arg("openssl req -x509 -sha256 -nodes -days 365 -newkey rsa:4096 -keyout private.key -out certificate.crt -subj '/C=US/ST=CA/L=Rocklin/CN=localhost/emailAddress=github@hollensbe.org'").
            current_dir(path).stdout(Stdio::null()).stderr(Stdio::null()).stdin(Stdio::null());

            assert!(command.spawn().unwrap().wait().unwrap().success());

            tempdir
        }

        fn assert_hello_world(tempdir: Arc<TempDir>, should_pass: bool) {
            let (addr_s, addr_r) = mpsc::sync_channel(1);
            let (s, r) = mpsc::sync_channel(1);

            thread::spawn(move || {
                let mut acceptor = SslAcceptor::mozilla_modern_v5(SslMethod::tls_server()).unwrap();
                acceptor
                    .set_private_key_file(tempdir.path().join("private.key"), SslFiletype::PEM)
                    .unwrap();
                acceptor
                    .set_certificate_chain_file(tempdir.path().join("certificate.crt"))
                    .unwrap();
                let acceptor = Arc::new(acceptor.build());
                let listener = TcpListener::bind("localhost:0").unwrap();
                addr_s.send(listener.local_addr().unwrap()).unwrap();
                drop(addr_s);

                for stream in listener.incoming() {
                    match stream {
                        Ok(stream) => {
                            let acceptor = acceptor.clone();
                            let s = s.clone();
                            thread::spawn(move || {
                                if let Ok(mut stream) = acceptor.accept(stream) {
                                    let mut result = Vec::new();
                                    stream.read_to_end(&mut result).unwrap();
                                    s.send(result).unwrap();
                                } else {
                                    s.send(vec![]).unwrap();
                                }
                            });
                        }
                        Err(e) => assert!(false, "{}", e),
                    }
                }
            });

            thread::spawn(move || {
                let addr = addr_r.recv().unwrap();

                let connector = SslConnector::builder(SslMethod::tls_client())
                    .unwrap()
                    .build();

                let stream = TcpStream::connect(addr).unwrap();
                if let Ok(mut stream) = connector.connect("localhost", stream.try_clone().unwrap())
                {
                    stream.write_all(b"Hello, World!").unwrap();
                    stream.flush().unwrap();
                    stream.shutdown().unwrap();
                } else {
                    stream.shutdown(std::net::Shutdown::Both).unwrap();
                }
            });

            let result = r.recv().unwrap();
            if should_pass {
                assert_eq!(result, b"Hello, World!");
            } else {
                assert_eq!(result.len(), 0);
            }
        }

        #[test]
        fn test_install_cert() {
            let tempdir = Arc::new(make_cert());
            let chain = std::fs::read(tempdir.path().join("certificate.crt")).unwrap();
            crate::install_platform(
                crate::StoreFlavor::System,
                "truststore-test-cert",
                chain.clone(),
            )
            .unwrap();

            assert_hello_world(tempdir.clone(), true);
            crate::uninstall_platform(crate::StoreFlavor::System, "truststore-test-cert").unwrap();
            assert_hello_world(tempdir.clone(), false);
        }
    }
}
