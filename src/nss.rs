#![allow(dead_code, unused_variables)]

use pathsearch::find_executable_in_path;
use std::path::PathBuf;

#[cfg(target_os = "macos")]
mod macos {
    pub(crate) fn find_certutil_sys() -> Option<PathBuf> {
        // FIXME derive from https://github.com/FiloSottile/mkcert/blob/master/truststore_nss.go#L49
        return None;
    }
}

#[cfg(not(target_os = "macos"))]
mod others {
    use std::path::PathBuf;

    pub(crate) fn find_certutil_sys() -> Option<PathBuf> {
        None
    }
}

#[cfg(target_os = "macos")]
use macos as sys;
#[cfg(not(target_os = "macos"))]
use others as sys;

pub(crate) fn install_nss(
    cert_filename: &'static str,
    cert: Vec<u8>,
) -> Result<(), std::io::Error> {
    Ok(())
}

fn find_certutil() -> Option<PathBuf> {
    if let Some(certutil) = find_executable_in_path("certutil") {
        return Some(certutil);
    }

    sys::find_certutil_sys()
}
