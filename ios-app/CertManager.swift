import Foundation
import SideInstallerFFI

/// One iOS development certificate, decoded from `si_cert_list`'s JSON, where
/// Apple's optionals arrive flattened to "".
struct DevCert: Identifiable, Decodable, Equatable {
    let name: String
    let serialNumber: String
    let machineName: String
    let machineId: String
    let certificateId: String
    let platform: String
    let status: String
    /// RFC3339 expiry (e.g. `2027-01-01T00:00:00Z`), or "" if Apple omitted it.
    let expiration: String

    enum CodingKeys: String, CodingKey {
        case name
        case serialNumber = "serial_number"
        case machineName = "machine_name"
        case machineId = "machine_id"
        case certificateId = "certificate_id"
        case platform
        case status
        case expiration
    }

    /// Stable identity: the serial revocation keys on, or the certificate id.
    var id: String { serialNumber.isEmpty ? certificateId : serialNumber }

    var displayName: String { name.isEmpty ? L("Unnamed certificate") : name }

    /// The machine Apple tagged the certificate with, if any.
    var machineLabel: String? {
        machineName.isEmpty ? nil : machineName
    }

    /// `expiration` parsed to a `Date`, if present and well-formed.
    var expiresAt: Date? {
        guard !expiration.isEmpty else { return nil }
        let f = ISO8601DateFormatter()
        f.formatOptions = [.withInternetDateTime]
        return f.date(from: expiration)
            ?? ISO8601DateFormatter().date(from: expiration)
    }

    /// True once the expiry date is in the past.
    var isExpired: Bool {
        guard let date = expiresAt else { return false }
        return date < Date()
    }
}

/// The `.p12` `CertManager.exportP12` wrote, for the share sheet.
struct ExportedP12: Identifiable {
    let url: URL
    var id: URL { url }
}

/// Lists, revokes and exports the Apple ID's development certificates, using
/// the engine's credentials and 2FA prompt. Developer-portal only (no device);
/// blocking FFI calls run on a background queue.
final class CertManager: ObservableObject {

    /// The machine name SideInstaller's certificates are made under (what the
    /// install flow passes to `si_apple_signin`). Only those can be exported.
    static let machineName = "SideInstaller"

    @Published private(set) var certs: [DevCert] = []
    @Published private(set) var isSignedIn = false
    @Published private(set) var teamSummary: String?
    /// Sign-in or list in progress.
    @Published private(set) var isWorking = false
    /// `id` of the certificate currently being revoked, if any.
    @Published private(set) var revokingID: String?
    /// `id` of the certificate currently being exported, if any.
    @Published private(set) var exportingID: String?
    /// The last export, until the share sheet showing it closes.
    @Published var exportedP12: ExportedP12?
    @Published var lastError: String?
    /// True once a list has been fetched (tells "not loaded" apart from "empty").
    @Published private(set) var hasLoaded = false

    private var session: OpaquePointer?            // CertSession*
    private let queue = DispatchQueue(label: "sideinstaller.certs")

    private var engine: Engine { Engine.shared }

    /// Limits `autoLoad` to one attempt, so a failed sign-in or dismissed 2FA
    /// prompt doesn't come back every time the page opens.
    private var didAutoLoad = false

    deinit {
        if let session { si_cert_session_free(session) }
    }

    // MARK: - Popups

    /// What went wrong last, as a popup `RootView` stacks over the app.
    var popups: [ToolPopup] { lastError.map { [.error($0)] } ?? [] }

    func closePopup(_ popup: ToolPopup) { lastError = nil }

    // MARK: - Public actions

    /// Loads certificates when the page opens. Does nothing if no Apple ID is
    /// saved.
    @MainActor
    func autoLoad() {
        guard !didAutoLoad, !hasLoaded, !isWorking, revokingID == nil, exportingID == nil else { return }
        guard !engine.normalizedAppleID.isEmpty, !engine.applePassword.isEmpty else { return }
        didAutoLoad = true
        loadCerts()
    }

    /// Sign in if needed and reload the list; `then` runs only if it arrived.
    @MainActor
    func loadCerts(then: (() -> Void)? = nil) {
        guard !isWorking, revokingID == nil, exportingID == nil else { return }
        let id = engine.normalizedAppleID, pw = engine.applePassword
        guard !id.isEmpty, !pw.isEmpty else {
            lastError = L("No Apple ID saved. Add one in Settings › Account.")
            return
        }
        isWorking = true
        lastError = nil
        engine.log("=== Certificates: loading ===")
        Task { @MainActor in
            do {
                if session == nil { try await signIn(id: id, pw: pw) }
                let list = try await onQueue { try self.performList() }
                certs = list
                hasLoaded = true
                engine.log("Certificates: \(list.count) iOS development certificate(s).")
                isWorking = false
                then?()
                return
            } catch is CancellationError {
                // Not currently cancellable; handled for consistency with Engine.
            } catch {
                lastError = short(error)
                engine.log("⛔️ Certificates: \(lastError ?? "failed")")
            }
            isWorking = false
        }
    }

    /// Revokes a certificate and refreshes the list. `onSuccess` (e.g. retrying
    /// the install) runs only if Apple accepted the revocation.
    @MainActor
    func revoke(_ cert: DevCert, onSuccess: (() -> Void)? = nil) {
        guard session != nil, revokingID == nil, exportingID == nil, !isWorking else { return }
        let serial = cert.serialNumber
        guard !serial.isEmpty else {
            lastError = L("This certificate has no serial number, so it can't be revoked.")
            return
        }
        revokingID = cert.id
        lastError = nil
        engine.log("Certificates: revoking \(cert.displayName) (\(serial)) …")
        Task { @MainActor in
            var revoked = false
            do {
                try await onQueue { try self.performRevoke(serial: serial) }
                revoked = true
                engine.log("Certificates: revoked \(cert.displayName).")
                let list = try await onQueue { try self.performList() }
                certs = list
            } catch {
                lastError = short(error)
                engine.log("⛔️ Revoke failed: \(lastError ?? "")")
            }
            revokingID = nil
            // Run `onSuccess` if the revoke succeeded, even if the refresh failed.
            if revoked { onSuccess?() }
        }
    }

    /// Whether `cert` may be the one SideInstaller made on this iPhone, the only
    /// kind whose private key is here to export. Another iPhone's SideInstaller
    /// certificate has the same machine name; `exportP12` tells them apart.
    func canExport(_ cert: DevCert) -> Bool {
        cert.machineName == Self.machineName && !cert.serialNumber.isEmpty
    }

    /// Exports `cert` with its private key as a `.p12` encrypted with
    /// `password`, then offers it in `exportedP12`. Asks Apple only for the
    /// certificate list; nothing is created or revoked.
    @MainActor
    func exportP12(_ cert: DevCert, password: String) {
        guard session != nil, exportingID == nil, revokingID == nil, !isWorking else { return }
        guard !password.isEmpty else {
            lastError = L("Enter a password for the .p12 file.")
            return
        }
        exportingID = cert.id
        lastError = nil
        engine.log("Certificates: exporting \(cert.displayName) as .p12 …")
        Task { @MainActor in
            do {
                let (serial, data) = try await onQueue {
                    try self.performExport(serial: cert.serialNumber, password: password)
                }
                let url = try Self.writeExport(data, serial: serial)
                exportedP12 = ExportedP12(url: url)
                engine.log("Certificates: exported \(cert.displayName) (\(data.count) bytes).")
            } catch {
                lastError = short(error)
                engine.log("⛔️ Export failed: \(lastError ?? "")")
            }
            exportingID = nil
        }
    }

    /// Deletes the exported file once the share sheet closes; whatever it was
    /// shared to or saved in keeps its own copy.
    @MainActor
    func discardExport() {
        if let url = exportedP12?.url {
            try? FileManager.default.removeItem(at: url.deletingLastPathComponent())
        }
        exportedP12 = nil
    }

    /// Loads the list if needed, then runs `then`. Used by the Install screen's
    /// revoke chooser.
    @MainActor
    func ensureLoaded(then: @escaping () -> Void) {
        guard !isWorking, revokingID == nil, exportingID == nil else { return }
        if hasLoaded, session != nil {
            then()
            return
        }
        loadCerts(then: then)
    }

    /// Frees the session and clears the list (e.g. when the Apple ID changes).
    /// No-op if not signed in.
    @MainActor
    func signOut() {
        guard let session else { return }
        si_cert_session_free(session)
        self.session = nil
        isSignedIn = false
        teamSummary = nil
        certs = []
        hasLoaded = false
        didAutoLoad = false
        lastError = nil
        engine.log("Certificates: signed out.")
    }

    // MARK: - Sign-in

    @MainActor
    private func signIn(id: String, pw: String) async throws {
        // Try each anisette server; a credential or 2FA error stops the loop.
        let servers = anisetteCandidates()
        let dir = storageDir
        engine.twoFactorWasCancelled = false
        var lastError = "no anisette servers configured"
        var appleRefusals = 0
        var appleUnreachable = 0

        for (idx, ani) in servers.enumerated() {
            do {
                let summary = try await onQueue {
                    try self.performSignIn(id: id, pw: pw, ani: ani, dir: dir)
                }
                engine.anisetteURL = ani               // stick with what worked
                teamSummary = summary
                isSignedIn = true
                engine.log("Certificates: signed in (\(summary)).")
                return
            } catch let error as EngineError {
                lastError = error.errorDescription ?? "sign-in failed"
                if engine.twoFactorWasCancelled {
                    engine.log("Two-factor verification cancelled — stopping.")
                    throw EngineError.message(L("Two-factor verification was cancelled."))
                }
                if Engine.isAccountLocked(lastError) {
                    engine.log("Apple has locked this Apple Account: \(lastError)")
                    throw EngineError.accountLocked
                }
                if Engine.isEmailUnverifiedError(lastError) {
                    engine.log("Apple wants this Apple Account's email address verified first: \(lastError)")
                    throw EngineError.emailUnverified
                }
                if Engine.isCredentialError(lastError) {
                    engine.log("Apple ID credentials rejected: \(lastError)")
                    throw EngineError.message(Engine.credentialErrorMessage)
                }
                engine.log("Certificates: anisette \(idx + 1)/\(servers.count) failed: \(lastError)")
                if Engine.isAppleRateLimit(lastError) {
                    engine.log("Certificates: Apple is rate-limiting sign-in (HTTP 429) — stopping.")
                    throw EngineError.message(Engine.appleRateLimitMessage)
                }
                // Apple refusing the request fails the same on every server.
                if Engine.isAppleServiceRefusal(lastError) {
                    appleRefusals += 1
                    if appleRefusals >= 2 {
                        engine.log("Certificates: Apple's sign-in server refused \(appleRefusals) attempts with HTTP 503 — stopping.")
                        throw EngineError.message(Engine.appleServiceRefusalMessage)
                    }
                }
                // Every anisette server starts with the same request to Apple, so
                // when that can't even be sent, more of them won't help.
                if Engine.isAppleUnreachable(lastError) {
                    appleUnreachable += 1
                    if let message = await engine.appleUnreachableStop(
                        failures: appleUnreachable, logPrefix: "Certificates: ") {
                        throw EngineError.message(message)
                    }
                } else {
                    appleUnreachable = 0
                }
            }
        }
        let tried = servers.count == 1
            ? L("the anisette server")
            : L("all %d anisette servers", servers.count)
        throw EngineError.message(L("Apple ID sign-in failed on %@. Last error: %@", tried, lastError))
    }

    /// One sign-in attempt against a specific anisette server.
    private func performSignIn(id: String, pw: String, ani: String, dir: String) throws -> String {
        defer { engine.endTwoFactor() }
        var newSession: OpaquePointer?
        var summary: UnsafeMutablePointer<CChar>?
        var error: UnsafeMutablePointer<CChar>?
        let rc = si_cert_signin(id, pw, ani, Self.machineName, dir,
                                certTwoFactorCallback, nil,
                                &newSession, &summary, &error)
        if rc == 0 {
            if let old = self.session { si_cert_session_free(old) }
            self.session = newSession
            let s = summary.map { String(cString: $0) } ?? ""
            summary.map { si_string_free($0) }
            return s
        } else {
            let msg = error.map { String(cString: $0) } ?? "rc=\(rc)"
            error.map { si_string_free($0) }
            throw EngineError.message(msg)
        }
    }

    // MARK: - List / revoke FFI

    private func performList() throws -> [DevCert] {
        guard let session = self.session else { throw EngineError.message("Not signed in.") }
        var json: UnsafeMutablePointer<CChar>?
        var error: UnsafeMutablePointer<CChar>?
        let rc = si_cert_list(session, &json, &error)
        if rc == 0 {
            let s = json.map { String(cString: $0) } ?? "[]"
            json.map { si_string_free($0) }
            do {
                return try JSONDecoder().decode([DevCert].self, from: Data(s.utf8))
            } catch {
                throw EngineError.message("Couldn't read the certificate list: \(error)")
            }
        } else {
            let msg = error.map { String(cString: $0) } ?? "rc=\(rc)"
            error.map { si_string_free($0) }
            throw EngineError.message("Listing certificates failed: \(msg)")
        }
    }

    private func performRevoke(serial: String) throws {
        guard let session = self.session else { throw EngineError.message("Not signed in.") }
        var error: UnsafeMutablePointer<CChar>?
        let rc = si_cert_revoke(session, serial, &error)
        if rc != 0 {
            let msg = error.map { String(cString: $0) } ?? "rc=\(rc)"
            error.map { si_string_free($0) }
            throw EngineError.message("Revoke failed: \(msg)")
        }
    }

    /// The archive for `serial` and the serial it actually holds.
    private func performExport(serial: String, password: String) throws -> (String, Data) {
        guard let session = self.session else { throw EngineError.message("Not signed in.") }
        var json: UnsafeMutablePointer<CChar>?
        var error: UnsafeMutablePointer<CChar>?
        let rc = si_cert_export_p12(session, serial, password, &json, &error)
        let msg = error.map { String(cString: $0) } ?? "rc=\(rc)"
        error.map { si_string_free($0) }
        guard rc == 0 else {
            engine.log("Certificates: export refused: \(msg)")
            switch rc {
            case SI_CERT_EXPORT_NONE_HERE:
                throw EngineError.message(L("There's no certificate to export on this iPhone. Only a certificate SideInstaller made on this iPhone can be exported, since Apple never has its private key. If it was revoked, install SideStore with SideInstaller again to make a new one."))
            case SI_CERT_EXPORT_OTHER_DEVICE:
                throw EngineError.message(L("SideInstaller made this certificate on another device, so its private key isn't on this iPhone. Export it from that device."))
            default:
                throw EngineError.message("Export failed: \(msg)")
            }
        }
        let s = json.map { String(cString: $0) } ?? ""
        json.map { si_string_free($0) }
        struct Reply: Decodable {
            let serialNumber: String
            let p12: String
            enum CodingKeys: String, CodingKey {
                case serialNumber = "serial_number"
                case p12
            }
        }
        guard let reply = try? JSONDecoder().decode(Reply.self, from: Data(s.utf8)),
              let data = Data(base64Encoded: reply.p12) else {
            throw EngineError.message("Couldn't read the exported certificate.")
        }
        return (reply.serialNumber, data)
    }

    /// Writes the archive to a folder of its own in tmp, which `discardExport`
    /// removes. Named after the serial, so two exports can't be mixed up.
    private static func writeExport(_ data: Data, serial: String) throws -> URL {
        let dir = FileManager.default.temporaryDirectory
            .appendingPathComponent("p12-export-\(UUID().uuidString)", isDirectory: true)
        let url = dir.appendingPathComponent("SideInstaller-\(serial.prefix(8)).p12")
        do {
            try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
            try data.write(to: url, options: [.atomic, .completeFileProtection])
        } catch {
            throw EngineError.message(L("Couldn't save the .p12 file: %@", error.localizedDescription))
        }
        return url
    }

    // MARK: - Helpers

    /// Anisette addresses to try, the engine's current pick first.
    private func anisetteCandidates() -> [String] {
        var seen = Set<String>()
        var out: [String] = []
        for addr in [engine.anisetteURL] + engine.anisetteServers.map(\.address) {
            let a = addr.trimmingCharacters(in: .whitespacesAndNewlines)
            if !a.isEmpty, seen.insert(a).inserted { out.append(a) }
        }
        return out
    }

    /// Same isideload storage as the install flow.
    private var storageDir: String {
        PrivateStore.isideload.path
    }

    private func short(_ error: Error) -> String {
        (error as? LocalizedError)?.errorDescription ?? String(describing: error)
    }

    /// Bridge a blocking FFI body on the cert queue to async.
    private func onQueue<T>(_ work: @escaping () throws -> T) async throws -> T {
        try await withCheckedThrowingContinuation { cont in
            queue.async {
                do { cont.resume(returning: try work()) }
                catch { cont.resume(throwing: error) }
            }
        }
    }
}

// MARK: - C 2FA callback

/// Bridges a 2FA request during cert sign-in to the engine's shared prompt.
private let certTwoFactorCallback: SITwoFactorCb = { _, request, outBuf, bufLen in
    Engine.shared.answerTwoFactor(request: request, outBuf: outBuf, len: Int(bufLen))
}
