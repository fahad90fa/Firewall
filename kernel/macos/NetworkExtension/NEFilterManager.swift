//
//  NEFilterManager.swift
//  Unified Firewall — installing and activating the content filter.
//
//  This is the code that runs in the *containing app*, not in the extension.
//  On macOS a Network Extension cannot install itself: an app has to request
//  activation, the user (or an MDM profile) has to approve it, and only then
//  does the filter configuration take effect.
//
//  # The approval problem, stated honestly
//
//  On an unmanaged Mac the first activation shows a system prompt, and the
//  user can decline. There is no way around this and no API to suppress it. A
//  host firewall that a user can decline is not much of a control, which is why
//  the deployment documentation says plainly that production installs need an
//  MDM profile pre-approving the team identifier — and why this code reports
//  the pending state rather than pretending activation succeeded.
//
//  # Why the configuration is loaded before it is modified
//
//  `NEFilterManager.shared()` starts empty. Writing to it without loading first
//  silently discards whatever configuration is already installed, which on a
//  machine that already has this filter means replacing a working config with a
//  partial one. Load, mutate, save is the only correct order.
//

import Foundation
import NetworkExtension
import SystemExtensions
import os.log

/// The states an operator needs to distinguish. "Not running" is three
/// different problems with three different fixes, and collapsing them into one
/// error is how a support ticket becomes an afternoon.
enum UFWFilterState: Equatable {
    case notInstalled
    /// The extension is installed but the user has not approved it. The fix is
    /// System Settings, or an MDM profile.
    case awaitingApproval
    case installedDisabled
    case active
    case failed(String)
}

final class UFWFilterManager: NSObject {
    private let log = Logger(subsystem: "com.unifiedfirewall.app", category: "manager")

    static let extensionBundleID = "com.unifiedfirewall.extension"

    private(set) var state: UFWFilterState = .notInstalled
    var onStateChange: ((UFWFilterState) -> Void)?

    // MARK: Activation

    /// Request activation of the system extension. The result arrives through
    /// the delegate below, possibly after a user interaction, possibly after a
    /// reboot.
    func activate() {
        let request = OSSystemExtensionRequest.activationRequest(
            forExtensionWithIdentifier: Self.extensionBundleID,
            queue: .main)
        request.delegate = self
        OSSystemExtensionManager.shared.submitRequest(request)
        log.info("submitted activation request for \(Self.extensionBundleID, privacy: .public)")
    }

    func deactivate() {
        let request = OSSystemExtensionRequest.deactivationRequest(
            forExtensionWithIdentifier: Self.extensionBundleID,
            queue: .main)
        request.delegate = self
        OSSystemExtensionManager.shared.submitRequest(request)
    }

    // MARK: Filter configuration

    /// Install and enable the content filter configuration.
    func enableFilter(completion: @escaping (Result<Void, Error>) -> Void) {
        // Load first. See the file header: writing to an unloaded shared
        // manager discards whatever is already installed.
        NEFilterManager.shared().loadFromPreferences { [weak self] error in
            guard let self else { return }
            if let error {
                self.update(.failed("loading filter preferences: \(error.localizedDescription)"))
                completion(.failure(error))
                return
            }

            if NEFilterManager.shared().providerConfiguration == nil {
                let configuration = NEFilterProviderConfiguration()
                // Both, and this is a policy decision rather than a default:
                // socket filtering is what carries application identity, and
                // packet filtering is the only way to see ICMP. Enabling only
                // the first would make every packet-stage rule silently
                // inert.
                configuration.filterSockets = true
                configuration.filterPackets = true
                NEFilterManager.shared().providerConfiguration = configuration
                NEFilterManager.shared().localizedDescription = "Unified Firewall"
            }
            NEFilterManager.shared().isEnabled = true

            NEFilterManager.shared().saveToPreferences { error in
                if let error {
                    self.update(.failed("saving filter preferences: \(error.localizedDescription)"))
                    completion(.failure(error))
                } else {
                    self.update(.active)
                    completion(.success(()))
                }
            }
        }
    }

    func disableFilter(completion: @escaping (Result<Void, Error>) -> Void) {
        NEFilterManager.shared().loadFromPreferences { [weak self] error in
            if let error {
                completion(.failure(error))
                return
            }
            NEFilterManager.shared().isEnabled = false
            NEFilterManager.shared().saveToPreferences { error in
                if let error {
                    completion(.failure(error))
                } else {
                    self?.update(.installedDisabled)
                    completion(.success(()))
                }
            }
        }
    }

    func refreshState(completion: @escaping (UFWFilterState) -> Void) {
        NEFilterManager.shared().loadFromPreferences { [weak self] error in
            guard let self else { return }
            if let error {
                let state = UFWFilterState.failed(error.localizedDescription)
                self.update(state)
                completion(state)
                return
            }
            let manager = NEFilterManager.shared()
            let state: UFWFilterState
            if manager.providerConfiguration == nil {
                state = .notInstalled
            } else if manager.isEnabled {
                state = .active
            } else {
                state = .installedDisabled
            }
            self.update(state)
            completion(state)
        }
    }

    private func update(_ new: UFWFilterState) {
        state = new
        onStateChange?(new)
    }
}

extension UFWFilterManager: OSSystemExtensionRequestDelegate {
    func request(_ request: OSSystemExtensionRequest,
                 actionForReplacingExtension existing: OSSystemExtensionProperties,
                 withExtension replacement: OSSystemExtensionProperties)
        -> OSSystemExtensionRequest.ReplacementAction {
        log.info("replacing extension \(existing.bundleVersion, privacy: .public) with \(replacement.bundleVersion, privacy: .public)")
        // Always replace. A firewall extension that refuses to upgrade because
        // the version comparison looked wrong is a firewall stuck on an old
        // policy ABI, which is worse than either version.
        return .replace
    }

    func requestNeedsUserApproval(_ request: OSSystemExtensionRequest) {
        // Distinct from failure, and the distinction matters: nothing is wrong,
        // somebody just has to click. Reporting it as an error sends operators
        // looking for a bug.
        log.notice("extension needs user approval in System Settings > Privacy & Security")
        update(.awaitingApproval)
    }

    func request(_ request: OSSystemExtensionRequest,
                 didFinishWithResult result: OSSystemExtensionRequest.Result) {
        switch result {
        case .completed:
            log.info("extension activated")
            enableFilter { _ in }
        case .willCompleteAfterReboot:
            log.notice("extension will activate after reboot")
            update(.awaitingApproval)
        @unknown default:
            update(.failed("unrecognised activation result"))
        }
    }

    func request(_ request: OSSystemExtensionRequest, didFailWithError error: Error) {
        log.error("extension activation failed: \(error.localizedDescription, privacy: .public)")
        update(.failed(error.localizedDescription))
    }
}
