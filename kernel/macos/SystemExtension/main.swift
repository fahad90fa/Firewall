//
//  main.swift
//  Unified Firewall — system extension entry point.
//
//  Named `main.swift` because it carries top-level code: Swift permits
//  executable statements at file scope only in a file with this name, and the
//  `startSystemExtensionMode()` + `dispatchMain()` below are exactly that.
//
//  A Network Extension provider does not have a `main` of its own. The system
//  loads the bundle, reads NEProviderClasses from Info.plist, instantiates the
//  named class, and drives it through the NEFilterDataProvider callbacks. This
//  file exists to start the run loop the provider's asynchronous work needs,
//  and to do the two things that must happen before any flow is judged.
//
//  # Order matters here
//
//  The provider comes up with the policy compiled into it, so there is never a
//  moment when the extension is running and enforcing nothing. The daemon
//  replaces it moments later. If instead the extension waited for a policy
//  before it began filtering, the window between activation and the daemon's
//  first push would be a window with no firewall — small, but exactly the
//  window a machine reboots into.
//

import Foundation
import NetworkExtension
import os.log

private let log = Logger(subsystem: "com.unifiedfirewall.extension", category: "main")

autoreleasepool {
    log.info("unified firewall system extension starting")

    // `NEProvider.startSystemExtensionMode()` registers the provider classes
    // declared in Info.plist with the system. Everything after this point is
    // driven by callbacks; the run loop below is what keeps the process alive
    // to receive them.
    NEProvider.startSystemExtensionMode()
}

// Not `RunLoop.main.run()` on its own: the provider's queues need the main run
// loop live for the process's lifetime, and returning from here would tear
// down the extension the moment activation completed.
dispatchMain()
