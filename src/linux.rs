#![allow(dead_code)]
use std::{
    io::{Error, ErrorKind},
    path::PathBuf,
    process::Command,
};

use pathsearch::find_executable_in_path;

/// Installs the cert at the proper location
pub(crate) fn install_platform(cert_filename: &'static str, cert: Vec<u8>) -> Result<(), Error> {
    let trust_info = system_trust_info(cert_filename)?;

    std::fs::write(trust_info.create, cert)?;
    update_certs(trust_info.command)
}

/// Uninstalls the cert from the proper location. Error is sent if it it can't, you are
/// responsible for dealing with it.
pub(crate) fn uninstall_platform(cert_filename: &'static str) -> Result<(), Error> {
    let trust_info = system_trust_info(cert_filename)?;

    std::fs::remove_file(trust_info.create)?;

    if let Some(remove) = trust_info.remove {
        for r in remove {
            std::fs::remove_file(r)?;
        }
    }

    update_certs(trust_info.command)
}

// NOTE: this path must NOT be absolute. See std::path::PathBuf::push for more information
pub(crate) const FIREFOX_SUBDIR: &str = ".mozilla/firefox/";

fn update_certs(mut command: Command) -> Result<(), Error> {
    if command.spawn()?.wait()?.success() {
        Ok(())
    } else {
        Err(std::io::Error::new(
            ErrorKind::Other,
            "certificate update command was not success",
        ))
    }
}

struct TrustInfo {
    command: Command,
    create: String,
    remove: Option<Vec<String>>,
}

/// Returns a tuple of (Command for store, &str filename pattern of cert).
fn system_trust_info(cert_filename: &'static str) -> Result<TrustInfo, Error> {
    if PathBuf::from("/etc/pki/ca-trust/source/anchors/").exists() {
        let mut cmd = Command::new(find_executable_in_path("update-ca-trust").unwrap());
        cmd.arg("extract");

        let create_filename = format!(
            "/etc/pki/ca-trust/source/anchors/{}.pem",
            cert_filename.clone()
        );

        return Ok(TrustInfo {
            command: cmd,
            create: create_filename,
            remove: None,
        });
    }

    if PathBuf::from("/usr/local/share/ca-certificates/").exists() {
        return Ok(TrustInfo {
            command: Command::new(find_executable_in_path("update-ca-certificates").unwrap()),
            create: format!("/usr/local/share/ca-certificates/{}.crt", cert_filename),
            remove: Some(vec![format!("/etc/ssl/certs/{}.pem", cert_filename)]),
        });
    }

    if PathBuf::from("/etc/ca-certificates/trust-source/anchors/").exists() {
        let mut cmd = Command::new(find_executable_in_path("trust").unwrap());
        cmd.arg("extract-compat");
        return Ok(TrustInfo {
            command: cmd,
            create: format!(
                "/etc/ca-certificates/trust-source/anchors/{}.crt",
                cert_filename
            ),
            remove: None,
        });
    }

    if PathBuf::from("/usr/share/pki/trust/anchors").exists() {
        return Ok(TrustInfo {
            command: Command::new(find_executable_in_path("update-ca-certificates").unwrap()),
            create: format!("/usr/share/pki/trust/anchors/{}.pem", cert_filename),
            remove: None,
        });
    }

    Err(Error::new(
        ErrorKind::NotFound,
        "could not find certificate store",
    ))
}
