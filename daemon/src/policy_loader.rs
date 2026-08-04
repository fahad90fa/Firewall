//! Policy compilation and the hot-reload watcher.
//!
//! # Compile, verify, then install
//!
//! A reload is not "read the file and push it". It is: compile, refuse on any
//! error, refuse on warnings if configured to, verify cross-platform
//! equivalence, diff against what is installed, verify that applying the diff
//! reproduces the compiled policy, and only then send it. Each of those steps
//! exists because the failure it prevents is worse than a failed reload: an
//! operator whose edit did not take can see that and fix it, but an operator
//! whose edit installed something *different* from what they wrote cannot.
//!
//! A failed reload leaves the previous policy installed and enforcing. That is
//! the whole point of doing the work before touching the kernel.
//!
//! # Watching without inotify
//!
//! The watcher polls: it stats every policy file and compares
//! `(len, modified)` against the previous scan. `ReadDirectoryChangesW`,
//! `inotify` and `FSEvents` are all better, and all need FFI this crate does
//! not take. Polling at 500ms costs a handful of `stat` calls twice a second
//! and reloads a policy within half a second of an edit — which is not the
//! bottleneck in any deployment where a human is editing the file.
//!
//! The [`Watcher`] trait exists so a platform-native implementation can be
//! dropped in without touching the reload logic.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use ufw_policy_lang::{CompileOptions, Compilation};
use ufw_shared::policy_types::CompiledPolicy;

use crate::config::PolicyConfig;

/// Extension policy files must have.
pub const POLICY_EXTENSION: &str = "yaml";

/// Why a reload did not happen.
#[derive(Debug)]
pub enum LoadError {
    /// The policy directory could not be read.
    Io(std::io::Error),
    /// No policy files were found.
    NoPolicies(PathBuf),
    /// Compilation failed. The rendered diagnostics are attached.
    Compile { file: PathBuf, diagnostics: String },
    /// The three backends disagreed. Always a compiler defect.
    Equivalence { file: PathBuf, report: String },
}

impl std::fmt::Display for LoadError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LoadError::Io(e) => write!(f, "{e}"),
            LoadError::NoPolicies(dir) => write!(
                f,
                "no *.{POLICY_EXTENSION} policy files found in {}",
                dir.display()
            ),
            LoadError::Compile { file, diagnostics } => {
                write!(f, "{} failed to compile:\n{diagnostics}", file.display())
            }
            LoadError::Equivalence { file, report } => write!(
                f,
                "{} compiled, but the platform backends disagreed:\n{report}",
                file.display()
            ),
        }
    }
}

impl std::error::Error for LoadError {}

/// A compiled policy plus what compiling it had to say.
#[derive(Debug)]
pub struct LoadedPolicy {
    pub policy: CompiledPolicy,
    pub source: PathBuf,
    /// Rendered warnings and notes. Empty when the compile was silent.
    pub diagnostics: String,
    pub warning_count: usize,
    /// Scenarios the equivalence verifier checked, when it ran.
    pub equivalence_scenarios: usize,
    /// What the optimizer changed.
    pub rules_removed: usize,
    pub ebpf_eligible: usize,
}

/// Compile the policy a configuration points at.
///
/// `policy.files` names the files to load in order; an empty list means every
/// `*.yaml` in the directory, sorted, so the set is deterministic rather than
/// dependent on directory order.
pub fn load(config: &PolicyConfig) -> Result<LoadedPolicy, LoadError> {
    let files = resolve_files(config)?;
    let Some(primary) = files.first() else {
        return Err(LoadError::NoPolicies(config.dir.clone()));
    };

    // Multiple files are composed by generating a synthetic root that includes
    // each of them, rather than by concatenating text. Concatenation would
    // merge two `defaults:` blocks into a duplicate-key error and would put
    // every diagnostic at the wrong line.
    let (name, source_text, base_dir, source_path) = if files.len() == 1 {
        let text = std::fs::read_to_string(primary).map_err(LoadError::Io)?;
        let name = primary
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or("policy")
            .to_string();
        (
            name,
            text,
            primary.parent().unwrap_or(Path::new(".")).to_path_buf(),
            primary.clone(),
        )
    } else {
        let includes: Vec<String> = files
            .iter()
            .skip(1)
            .filter_map(|p| p.file_name().and_then(|n| n.to_str()).map(str::to_string))
            .collect();
        let primary_text = std::fs::read_to_string(primary).map_err(LoadError::Io)?;
        let mut text = String::new();
        if !includes.is_empty() {
            text.push_str(&format!("include: [{}]\n", includes.join(", ")));
        }
        text.push_str(&primary_text);
        (
            "policy".to_string(),
            text,
            config.dir.clone(),
            primary.clone(),
        )
    };

    let options = CompileOptions {
        deny_warnings: config.deny_warnings,
        verify_equivalence: config.verify_equivalence,
        ..Default::default()
    };

    let loader = ufw_policy_lang::FsLoader { base: base_dir };
    let result: Compilation =
        ufw_policy_lang::compile_with_loader(&name, &source_text, &options, &loader);

    let warning_count = result.diagnostics.warning_count();
    let diagnostics = if result.diagnostics.is_empty() {
        String::new()
    } else {
        result.diagnostics.render(&result.source)
    };

    let Some(policy) = result.policy else {
        return Err(LoadError::Compile { file: source_path, diagnostics });
    };

    if let Some(eq) = &result.equivalence {
        if !eq.is_equivalent() {
            return Err(LoadError::Equivalence {
                file: source_path,
                report: eq.render(),
            });
        }
    }

    Ok(LoadedPolicy {
        policy,
        source: source_path,
        diagnostics,
        warning_count,
        equivalence_scenarios: result
            .equivalence
            .as_ref()
            .map(|e| e.scenarios_checked)
            .unwrap_or(0),
        rules_removed: result.optimization.rules_removed(),
        ebpf_eligible: result.optimization.ebpf_eligible,
        })
}

/// The policy files to load, in order.
pub fn resolve_files(config: &PolicyConfig) -> Result<Vec<PathBuf>, LoadError> {
    if !config.files.is_empty() {
        return Ok(config.files.iter().map(|f| config.dir.join(f)).collect());
    }
    let mut files: Vec<PathBuf> = std::fs::read_dir(&config.dir)
        .map_err(LoadError::Io)?
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .filter(|p| {
            p.is_file()
                && p.extension()
                    .and_then(|e| e.to_str())
                    .is_some_and(|e| e.eq_ignore_ascii_case(POLICY_EXTENSION))
        })
        .collect();
    // Sorted so the composition order is a property of the filenames, not of
    // whatever order the filesystem hands them back in.
    files.sort();
    Ok(files)
}

// ===========================================================================
// Watching
// ===========================================================================

/// Detects changes to a set of files.
pub trait Watcher: Send {
    /// Whether anything changed since the last call. The first call
    /// establishes the baseline and reports no change.
    fn poll(&mut self) -> bool;
    fn name(&self) -> &'static str;
}

/// A fingerprint of one file: size and modification time.
///
/// Not a content hash. Hashing every policy file twice a second to detect an
/// edit is work in exchange for catching a rewrite that preserved both size
/// and mtime — which an editor does not do, and which a reload would catch on
/// the next real edit anyway.
type Fingerprint = (u64, Option<SystemTime>);

/// Polling watcher. Works everywhere; see the module docs for why it is the
/// default rather than a fallback.
#[derive(Debug)]
pub struct PollingWatcher {
    paths: Vec<PathBuf>,
    dir: PathBuf,
    last: BTreeMap<PathBuf, Fingerprint>,
    primed: bool,
}

impl PollingWatcher {
    pub fn new(dir: impl Into<PathBuf>, paths: Vec<PathBuf>) -> Self {
        PollingWatcher {
            paths,
            dir: dir.into(),
            last: BTreeMap::new(),
            primed: false,
        }
    }

    /// Watch every policy file the configuration resolves to.
    pub fn for_config(config: &PolicyConfig) -> Self {
        let paths = resolve_files(config).unwrap_or_default();
        PollingWatcher::new(config.dir.clone(), paths)
    }

    fn scan(&self) -> BTreeMap<PathBuf, Fingerprint> {
        let mut out = BTreeMap::new();

        // Watch the named files...
        for path in &self.paths {
            out.insert(path.clone(), fingerprint(path));
        }
        // ...and the directory, so a *new* policy file is noticed too. A
        // watcher that only knows about files that existed at startup misses
        // exactly the change an operator makes when adding a rule set.
        if let Ok(entries) = std::fs::read_dir(&self.dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path
                    .extension()
                    .and_then(|e| e.to_str())
                    .is_some_and(|e| e.eq_ignore_ascii_case(POLICY_EXTENSION))
                {
                    out.insert(path.clone(), fingerprint(&path));
                }
            }
        }
        out
    }
}

fn fingerprint(path: &Path) -> Fingerprint {
    match std::fs::metadata(path) {
        Ok(m) => (m.len(), m.modified().ok()),
        // A file that does not exist has a distinct fingerprint from one that
        // does, so deletion registers as a change.
        Err(_) => (u64::MAX, None),
    }
}

impl Watcher for PollingWatcher {
    fn poll(&mut self) -> bool {
        let current = self.scan();
        if !self.primed {
            self.last = current;
            self.primed = true;
            return false;
        }
        let changed = current != self.last;
        self.last = current;
        changed
    }

    fn name(&self) -> &'static str {
        "polling"
    }
}

/// A watcher that never reports a change, for `hot_reload = false`.
#[derive(Debug, Default)]
pub struct NullWatcher;

impl Watcher for NullWatcher {
    fn poll(&mut self) -> bool {
        false
    }

    fn name(&self) -> &'static str {
        "disabled"
    }
}

/// Build the watcher a configuration asks for.
pub fn watcher_for(config: &PolicyConfig) -> Box<dyn Watcher> {
    if config.hot_reload {
        Box::new(PollingWatcher::for_config(config))
    } else {
        Box::new(NullWatcher)
    }
}

/// Poll interval, as a `Duration`.
pub fn watch_interval(config: &PolicyConfig) -> Duration {
    Duration::from_millis(config.watch_interval_ms.max(50))
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Fixture {
        dir: PathBuf,
    }

    impl Fixture {
        fn new(name: &str) -> Self {
            let dir = std::env::temp_dir().join(format!(
                "ufw-policy-{}-{}-{name}",
                std::process::id(),
                ufw_shared::now_us()
            ));
            std::fs::create_dir_all(&dir).unwrap();
            Fixture { dir }
        }

        fn write(&self, name: &str, text: &str) -> PathBuf {
            let path = self.dir.join(name);
            std::fs::write(&path, text).unwrap();
            path
        }

        fn config(&self) -> PolicyConfig {
            PolicyConfig {
                dir: self.dir.clone(),
                files: Vec::new(),
                signature_dir: self.dir.clone(),
                hot_reload: true,
                watch_interval_ms: 50,
                deny_warnings: false,
                verify_equivalence: true,
            }
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.dir);
        }
    }

    const GOOD: &str = "version: 1\n\
                        defaults:\n  action: deny\n\
                        rules:\n\
                        \x20 - id: allow-dns\n    action: allow\n    protocol: udp\n\
                        \x20   destination:\n      ports: [53]\n";

    #[test]
    fn a_valid_policy_compiles_and_reports_what_it_did() {
        let f = Fixture::new("good");
        f.write("base.yaml", GOOD);
        let loaded = load(&f.config()).expect("compiles");
        assert_eq!(loaded.policy.rules.len(), 1);
        assert!(loaded.equivalence_scenarios > 0, "equivalence must have run");
        assert!(loaded.source.ends_with("base.yaml"));
    }

    #[test]
    fn a_broken_policy_fails_with_rendered_diagnostics() {
        let f = Fixture::new("broken");
        f.write("base.yaml", "version: 1\nrules:\n  - id: a\n");
        let err = load(&f.config()).unwrap_err();
        let text = err.to_string();
        assert!(text.contains("failed to compile"));
        // The operator gets the actual diagnostic, not just "invalid".
        assert!(text.contains("E0201"), "{text}");
    }

    #[test]
    fn deny_warnings_turns_a_lint_into_a_failed_reload() {
        let f = Fixture::new("warn");
        // A wildcard allow at the packet layer is a warning, not an error.
        f.write(
            "base.yaml",
            "version: 1\ndefaults:\n  action: deny\nrules:\n  - id: a\n    action: allow\n",
        );

        let mut config = f.config();
        assert!(load(&config).is_ok());

        config.deny_warnings = true;
        assert!(load(&config).is_err(), "--deny-warnings must be enforced");
    }

    #[test]
    fn an_empty_directory_is_an_explicit_error() {
        let f = Fixture::new("empty");
        match load(&f.config()) {
            Err(LoadError::NoPolicies(dir)) => assert_eq!(dir, f.dir),
            other => panic!("expected NoPolicies, got {other:?}"),
        }
    }

    #[test]
    fn multiple_files_compose_through_includes() {
        let f = Fixture::new("multi");
        // Sorted order puts `a-main.yaml` first, so it is the root and the
        // rest become includes.
        f.write(
            "a-main.yaml",
            "version: 1\ndefaults:\n  action: deny\n\
             rules:\n  - id: local\n    action: allow\n    protocol: tcp\n\
             \x20   destination:\n      addresses: [corp]\n",
        );
        f.write(
            "b-groups.yaml",
            "version: 1\naddress_groups:\n  corp: [10.0.0.0/8]\n",
        );

        let loaded = load(&f.config()).expect("composes");
        let rule = &loaded.policy.rules[0];
        assert_eq!(rule.dest.cidrs.len(), 1, "the included group resolved");
    }

    #[test]
    fn an_explicit_file_list_is_honoured_in_order() {
        let f = Fixture::new("explicit");
        f.write("z-main.yaml", GOOD);
        f.write("a-ignored.yaml", "version: 1\nnonsense: true\n");

        let mut config = f.config();
        config.files = vec!["z-main.yaml".into()];
        let loaded = load(&config).expect("compiles");
        assert!(loaded.source.ends_with("z-main.yaml"));
    }

    #[test]
    fn files_are_resolved_in_sorted_order() {
        let f = Fixture::new("sorted");
        for name in ["c.yaml", "a.yaml", "b.yaml", "notes.txt"] {
            f.write(name, "version: 1\n");
        }
        let files = resolve_files(&f.config()).unwrap();
        let names: Vec<String> = files
            .iter()
            .map(|p| p.file_name().unwrap().to_string_lossy().to_string())
            .collect();
        assert_eq!(names, vec!["a.yaml", "b.yaml", "c.yaml"]);
    }

    #[test]
    fn the_watcher_reports_no_change_on_its_first_poll() {
        let f = Fixture::new("prime");
        f.write("base.yaml", GOOD);
        let mut w = PollingWatcher::for_config(&f.config());
        assert!(!w.poll(), "the first poll only establishes a baseline");
        assert!(!w.poll(), "an unchanged directory reports nothing");
    }

    #[test]
    fn the_watcher_notices_an_edit() {
        let f = Fixture::new("edit");
        let path = f.write("base.yaml", GOOD);
        let mut w = PollingWatcher::for_config(&f.config());
        w.poll();

        // A different length is enough; mtime granularity varies by
        // filesystem and this must not depend on it.
        std::fs::write(&path, format!("{GOOD}# edited\n")).unwrap();
        assert!(w.poll());
        assert!(!w.poll(), "the change is reported once");
    }

    #[test]
    fn the_watcher_notices_a_new_file() {
        let f = Fixture::new("added");
        f.write("base.yaml", GOOD);
        let mut w = PollingWatcher::for_config(&f.config());
        w.poll();

        f.write("extra.yaml", "version: 1\n");
        assert!(w.poll(), "a policy added after startup must trigger a reload");
    }

    #[test]
    fn the_watcher_notices_a_deletion() {
        let f = Fixture::new("deleted");
        let path = f.write("base.yaml", GOOD);
        let mut w = PollingWatcher::for_config(&f.config());
        w.poll();

        std::fs::remove_file(&path).unwrap();
        assert!(w.poll());
    }

    #[test]
    fn hot_reload_off_gives_a_watcher_that_never_fires() {
        let f = Fixture::new("off");
        f.write("base.yaml", GOOD);
        let mut config = f.config();
        config.hot_reload = false;
        let mut w = watcher_for(&config);
        assert_eq!(w.name(), "disabled");
        assert!(!w.poll());
    }
}
