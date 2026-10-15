//! Lists and revokes iOS development certificates via `isideload`'s
//! `DeveloperSession` (developer portal only, no device). `si_cert_signin` opens
//! a session on the first team, `si_cert_list` returns its certificates as JSON,
//! `si_cert_revoke` revokes one by serial number, and `si_cert_export_p12`
//! exports the one SideInstaller made on this iPhone as a PKCS#12 archive.

use std::ffi::{c_char, c_void};
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::path::{Path, PathBuf};

use base64::{prelude::BASE64_STANDARD, Engine as _};
use isideload::{
    dev::{
        certificates::{CertificatesApi, DevelopmentCertificate},
        developer_session::DeveloperSession,
        device_type::DeveloperDeviceType,
        teams::DeveloperTeam,
    },
    sideload::cert_identity::CertificateIdentity,
    util::fs_storage::FsStorage,
};
use serde::Serialize;

use crate::account::{make_2fa, TwoFactorCb, TwoFaCtx};
use crate::apple_session;
use crate::error_text::report_text;
use crate::ffi_util::{cstr, opt_str};

/// Opaque handle owning the runtime, developer session and selected team.
pub struct CertSession {
    // `pub(crate)` so `entitlements` can reuse this session and team instead of
    // signing in (and prompting for 2FA) again.
    pub(crate) rt: tokio::runtime::Runtime,
    pub(crate) dev: DeveloperSession,
    pub(crate) team: DeveloperTeam,
    /// The Apple ID as signed in with, which isideload keys the signing key by.
    email: String,
    /// The machine name SideInstaller's certificates are made under.
    machine_name: String,
    storage_dir: PathBuf,
}

// Used only through its own runtime, serialized by Swift on one queue.
unsafe impl Send for CertSession {}

/// A certificate flattened to plain strings, so Swift decodes no optionals.
#[derive(Serialize)]
struct CertInfo {
    name: String,
    serial_number: String,
    machine_name: String,
    machine_id: String,
    certificate_id: String,
    platform: String,
    status: String,
    /// RFC3339 expiry (e.g. `2027-01-01T00:00:00Z`), or "" if Apple omitted it.
    expiration: String,
}

impl From<&DevelopmentCertificate> for CertInfo {
    fn from(c: &DevelopmentCertificate) -> Self {
        let s = |o: &Option<String>| o.clone().unwrap_or_default();
        CertInfo {
            name: s(&c.name),
            serial_number: s(&c.serial_number),
            machine_name: s(&c.machine_name),
            machine_id: s(&c.machine_id),
            certificate_id: s(&c.certificate_id),
            platform: s(&c.certificate_platform),
            status: s(&c.status),
            // plist::Date's XML form is RFC3339 (e.g. 2027-01-01T00:00:00Z).
            expiration: c
                .expiration_date
                .as_ref()
                .map(|d| d.to_xml_format())
                .unwrap_or_default(),
        }
    }
}

/// Log in, open a developer session, and select the first team. Returns 0 on
/// success; free the session with `si_cert_session_free`.
///
/// # Safety
/// All `*const c_char` args must be null or valid C strings; the out pointers
/// must be valid and writable.
#[allow(clippy::too_many_arguments)]
pub unsafe fn cert_signin(
    apple_id: *const c_char,
    password: *const c_char,
    anisette_url: *const c_char,
    // Only read by `cert_export_p12`, to find the certificate made under it.
    machine_name: *const c_char,
    storage_dir: *const c_char,
    twofa_cb: TwoFactorCb,
    ctx: *mut c_void,
    out_session: *mut *mut CertSession,
    out_summary: *mut *mut c_char,
    out_error: *mut *mut c_char,
) -> i32 {
    let apple_id = opt_str(apple_id, "");
    let password = opt_str(password, "");
    let anisette_url = opt_str(anisette_url, "https://ani.sidestore.io");
    let machine_name = opt_str(machine_name, "SideInstaller");
    let storage_dir = opt_str(storage_dir, ".");
    let twofa = make_2fa(twofa_cb, TwoFaCtx(ctx));

    let result = catch_unwind(AssertUnwindSafe(|| {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .map_err(|e| format!("failed to start runtime: {e}"))?;

        let (dev, team, summary) = rt.block_on(async {
            // Always the active account, so the session is saved and reused.
            let (dev, teams) = apple_session::open(
                &apple_id,
                &password,
                &anisette_url,
                Path::new(&storage_dir),
                true,
                twofa,
                "Certs",
            )
            .await?;
            let team = teams
                .into_iter()
                .next()
                .ok_or_else(|| "no development teams on this Apple ID".to_string())?;
            tracing::info!("Certs: using team {}", team.team_id);

            let summary = format!(
                "team: {} ({})",
                team.name.as_deref().unwrap_or("<unnamed>"),
                team.team_id
            );
            Ok::<_, String>((dev, team, summary))
        })?;

        Ok::<_, String>((rt, dev, team, summary))
    }));

    match result {
        Ok(Ok((rt, dev, team, summary))) => {
            let session = Box::new(CertSession {
                rt,
                dev,
                team,
                email: apple_id,
                machine_name,
                storage_dir: PathBuf::from(storage_dir),
            });
            *out_session = Box::into_raw(session);
            *out_summary = cstr(summary);
            0
        }
        Ok(Err(e)) => {
            *out_error = cstr(e);
            1
        }
        Err(_) => {
            *out_error = cstr("panic during certificate sign-in");
            2
        }
    }
}

/// List the team's certificates as a JSON array of `CertInfo`.
///
/// # Safety
/// `session` must be a valid pointer from `cert_signin`; out pointers valid.
pub unsafe fn cert_list(
    session: *mut CertSession,
    out_json: *mut *mut c_char,
    out_error: *mut *mut c_char,
) -> i32 {
    if session.is_null() {
        *out_error = cstr("null session");
        return 2;
    }
    let session = &mut *session;

    let result = catch_unwind(AssertUnwindSafe(|| {
        session.rt.block_on(async {
            let certs = session
                .dev
                .list_ios_certs(&session.team)
                .await
                .map_err(|e| format!("list certs failed: {}", report_text(&e)))?;
            tracing::info!("Certs: {} iOS development certificate(s)", certs.len());
            let infos: Vec<CertInfo> = certs.iter().map(CertInfo::from).collect();
            serde_json::to_string(&infos).map_err(|e| format!("serialize certs: {e}"))
        })
    }));

    match result {
        Ok(Ok(json)) => {
            *out_json = cstr(json);
            0
        }
        Ok(Err(e)) => {
            *out_error = cstr(e);
            1
        }
        Err(_) => {
            *out_error = cstr("panic while listing certificates");
            2
        }
    }
}

/// Revoke the certificate with `serial_number`.
///
/// # Safety
/// `session` must be a valid pointer from `cert_signin`; `serial_number` a
/// valid C string; `out_error` valid and writable.
pub unsafe fn cert_revoke(
    session: *mut CertSession,
    serial_number: *const c_char,
    out_error: *mut *mut c_char,
) -> i32 {
    if session.is_null() {
        *out_error = cstr("null session");
        return 2;
    }
    let session = &mut *session;
    let serial = opt_str(serial_number, "");
    if serial.is_empty() {
        *out_error = cstr("empty serial number");
        return 2;
    }

    let result = catch_unwind(AssertUnwindSafe(|| {
        session.rt.block_on(async {
            tracing::info!("Certs: revoking certificate {serial}");
            session
                .dev
                .revoke_development_cert(&session.team, &serial, DeveloperDeviceType::Ios)
                .await
                .map_err(|e| format!("revoke failed: {}", report_text(&e)))?;
            Ok::<_, String>(())
        })
    }));

    match result {
        Ok(Ok(())) => {
            tracing::info!("Certs: revoked {serial}");
            0
        }
        Ok(Err(e)) => {
            *out_error = cstr(e);
            1
        }
        Err(_) => {
            *out_error = cstr("panic while revoking certificate");
            2
        }
    }
}

/// `cert_export_p12`'s answer: the archive and the certificate in it.
#[derive(Serialize)]
struct ExportedP12 {
    serial_number: String,
    /// Base64 of the PKCS#12 archive, encrypted with the caller's password.
    p12: String,
}

/// No certificate on the portal goes with a key SideInstaller made here.
pub const EXPORT_NONE_HERE: i32 = 3;
/// The certificate asked for isn't the one whose key is here.
pub const EXPORT_OTHER_DEVICE: i32 = 4;

/// Whether two certificate serials are the same number: Apple lists them in
/// upper-case hex, and leading zeros may or may not be written.
fn same_serial(a: &str, b: &str) -> bool {
    let norm = |s: &str| s.trim_start_matches('0').to_ascii_uppercase();
    norm(a) == norm(b)
}

/// Export the certificate SideInstaller made on this iPhone, with its private
/// key, as a PKCS#12 archive encrypted with `password`, for apps that sign with
/// one (Nyxian, Feather, …). On success `*out_json` is an [`ExportedP12`].
///
/// Only that certificate can be exported: Apple keeps a certificate, never its
/// key, which stays on the device that asked for it. `serial_number` is the
/// certificate the user picked; when it isn't that one, nothing is exported.
/// Asks Apple only for the certificate list, and never makes, revokes or
/// replaces a certificate, so it can't break anything signed with one.
///
/// Returns 0 on success, [`EXPORT_NONE_HERE`] when this iPhone has no key or
/// none of the account's certificates matches it (never made here, or
/// revoked), [`EXPORT_OTHER_DEVICE`] when `serial_number` is another
/// certificate, and 1 or 2 on other errors. `*out_error` is set on any failure.
///
/// # Safety
/// `session` must be a valid pointer from `cert_signin`; the C strings valid;
/// out pointers valid and writable.
pub unsafe fn cert_export_p12(
    session: *mut CertSession,
    serial_number: *const c_char,
    password: *const c_char,
    out_json: *mut *mut c_char,
    out_error: *mut *mut c_char,
) -> i32 {
    if session.is_null() {
        *out_error = cstr("null session");
        return 2;
    }
    let session = &mut *session;
    let wanted = opt_str(serial_number, "");
    let password = opt_str(password, "");
    if password.is_empty() {
        *out_error = cstr("empty password");
        return 2;
    }

    // Checked first: `retrieve_existing` would make and store a key that no
    // certificate goes with yet.
    let key = apple_session::account_dir(&session.storage_dir, &session.email).join("key");
    if !key.is_file() {
        tracing::info!("Certs: no signing key for this Apple ID on this device");
        *out_error =
            cstr("SideInstaller hasn't made a certificate for this Apple ID on this device");
        return EXPORT_NONE_HERE;
    }

    let result = catch_unwind(AssertUnwindSafe(|| {
        let storage = FsStorage::new(session.storage_dir.clone());
        session.rt.block_on(async {
            // `retrieve_existing` takes a failed lookup for no match, which
            // would blame a network error on the certificate; asking once here
            // reports it as it is.
            session
                .dev
                .list_ios_certs(&session.team)
                .await
                .map_err(|e| (1, format!("list certs failed: {}", report_text(&e))))?;

            let identity = CertificateIdentity::retrieve_existing(
                &session.machine_name,
                &session.email,
                &mut session.dev,
                &session.team,
                &storage,
            )
            .await
            .map_err(|e| (1, format!("certificate lookup failed: {}", report_text(&e))))?
            .ok_or_else(|| {
                (
                    EXPORT_NONE_HERE,
                    format!(
                        "no '{}' certificate on this Apple ID goes with the key on this device",
                        session.machine_name
                    ),
                )
            })?;

            let serial = identity.get_serial_number();
            if !wanted.is_empty() && !same_serial(&wanted, &serial) {
                return Err((
                    EXPORT_OTHER_DEVICE,
                    format!("certificate {wanted} isn't this device's (that's {serial})"),
                ));
            }

            let p12 = identity
                .as_p12(&password)
                .await
                .map_err(|e| (1, format!("failed to build the PKCS#12 archive: {e}")))?;
            tracing::info!(
                "Certs: exported certificate {serial} ({} byte p12)",
                p12.len()
            );
            serde_json::to_string(&ExportedP12 {
                serial_number: serial,
                p12: BASE64_STANDARD.encode(&p12),
            })
            .map_err(|e| (1, format!("serialize the export: {e}")))
        })
    }));

    match result {
        Ok(Ok(json)) => {
            *out_json = cstr(json);
            0
        }
        Ok(Err((rc, e))) => {
            *out_error = cstr(e);
            rc
        }
        Err(_) => {
            *out_error = cstr("panic while exporting the certificate");
            2
        }
    }
}

/// Free a `CertSession`.
///
/// # Safety
/// `session` must be null or a pointer from `cert_signin`.
pub unsafe fn cert_session_free(session: *mut CertSession) {
    if !session.is_null() {
        drop(Box::from_raw(session));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn serials_compare_as_numbers() {
        assert!(same_serial(
            "364D766243450DE16ED0CBBBF07FD9F2",
            "364d766243450de16ed0cbbbf07fd9f2"
        ));
        assert!(same_serial("0A1B", "A1B"));
        assert!(!same_serial("A1B", "A1C"));
    }
}
