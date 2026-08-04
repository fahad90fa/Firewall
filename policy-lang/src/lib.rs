//! The Unified Policy Language compiler.
//!
//! One policy source compiles to three kernel implementations. This crate is
//! the front half of that claim: it turns policy text into a
//! [`CompiledPolicy`] and then into platform-native artifacts for Windows,
//! Linux and macOS, and it can prove the three agree.
//!
//! # Pipeline
//!
//! ```text
//!   text ──▶ lexer ──▶ parser ──▶ semantic ──▶ optimizer ──▶ backends
//!             │          │           │            │            │
//!          tokens       AST     CompiledPolicy  smaller     artifacts
//!                                              CompiledPolicy   +
//!                                                          DecisionModel
//!                                                               │
//!                                                    equivalence verifier
//! ```
//!
//! Each phase collects diagnostics rather than failing at the first problem,
//! so one run reports everything wrong with a policy.
//!
//! # Usage
//!
//! ```
//! use ufw_policy_lang::{compile_str, CompileOptions};
//!
//! let source = r#"
//! version: 1
//! defaults:
//!   action: deny
//! rules:
//!   - id: allow-dns
//!     action: allow
//!     protocol: udp
//!     destination:
//!       ports: [53]
//! "#;
//!
//! let result = compile_str("example", source, &CompileOptions::default());
//! let policy = result.policy.as_ref().expect("compiles");
//! assert_eq!(policy.rules.len(), 1);
//! assert_eq!(result.artifacts.len(), 3);
//! assert!(result.equivalence.as_ref().unwrap().is_equivalent());
//! ```

#![forbid(unsafe_code)]

pub mod ast;
pub mod compiler;
pub mod error;
pub mod lexer;
pub mod optimizer;
pub mod parser;
pub mod semantic;

use std::collections::HashSet;
use std::path::{Path, PathBuf};

use ufw_shared::policy_types::CompiledPolicy;
use ufw_shared::Platform;

use crate::compiler::{Artifact, EquivalenceReport, Scenario};
use crate::error::{codes, Diagnostic, Diagnostics, SourceFile, Span};
use crate::optimizer::{OptimizationReport, OptimizerOptions};

/// Knobs for one compilation.
#[derive(Debug, Clone)]
pub struct CompileOptions {
    pub optimizer: OptimizerOptions,
    /// Platforms to generate artifacts for.
    pub platforms: Vec<Platform>,
    /// Run the cross-platform equivalence verifier. On by default: it is the
    /// only thing that turns "three backends" into "three backends that
    /// agree", and it costs milliseconds on a policy of realistic size.
    pub verify_equivalence: bool,
    /// Treat warnings as errors, for CI.
    pub deny_warnings: bool,
}

impl Default for CompileOptions {
    fn default() -> Self {
        CompileOptions {
            optimizer: OptimizerOptions::default(),
            platforms: Platform::ALL.to_vec(),
            verify_equivalence: true,
            deny_warnings: false,
        }
    }
}

impl CompileOptions {
    /// Compile for one platform only, skipping equivalence verification
    /// (which needs all three backends to be meaningful).
    pub fn single_platform(platform: Platform) -> Self {
        CompileOptions {
            platforms: vec![platform],
            verify_equivalence: false,
            ..Default::default()
        }
    }
}

/// Everything one compilation produced.
#[derive(Debug)]
pub struct Compilation {
    /// The source, retained so diagnostics can be rendered with snippets.
    pub source: SourceFile,
    /// `None` when compilation failed.
    pub policy: Option<CompiledPolicy>,
    pub artifacts: Vec<Artifact>,
    pub diagnostics: Diagnostics,
    pub optimization: OptimizationReport,
    pub equivalence: Option<EquivalenceReport>,
}

impl Compilation {
    pub fn is_ok(&self) -> bool {
        self.policy.is_some()
            && self
                .equivalence
                .as_ref()
                .map(|e| e.is_equivalent())
                .unwrap_or(true)
    }

    /// Diagnostics rendered with source snippets, plus the equivalence report.
    pub fn render(&self) -> String {
        let mut out = self.diagnostics.render(&self.source);
        if let Some(eq) = &self.equivalence {
            if !eq.is_equivalent() {
                out.push_str(&eq.render());
            }
        }
        out
    }

    pub fn artifact(&self, platform: Platform) -> Option<&Artifact> {
        self.artifacts.iter().find(|a| a.platform == platform)
    }
}

/// Compile policy text with no `include:` support.
pub fn compile_str(name: &str, text: &str, opts: &CompileOptions) -> Compilation {
    compile_with_loader(name, text, opts, &NoIncludes)
}

/// Compile a policy file from disk, resolving `include:` relative to it.
pub fn compile_file(path: &Path, opts: &CompileOptions) -> std::io::Result<Compilation> {
    let text = std::fs::read_to_string(path)?;
    let base = path.parent().unwrap_or(Path::new(".")).to_path_buf();
    let name = path
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("policy")
        .to_string();
    Ok(compile_with_loader(&name, &text, opts, &FsLoader { base }))
}

/// Resolves `include:` targets to policy text.
pub trait SourceLoader {
    /// Load an included policy. `Err` carries a human-readable reason.
    fn load(&self, target: &str) -> Result<String, String>;
}

/// A loader that rejects every include, for callers compiling a single
/// self-contained document.
#[derive(Debug)]
pub struct NoIncludes;

impl SourceLoader for NoIncludes {
    fn load(&self, target: &str) -> Result<String, String> {
        Err(format!(
            "`include: {target}` needs a filesystem context; compile this policy from a file"
        ))
    }
}

/// Loads includes from a base directory.
#[derive(Debug, Clone)]
pub struct FsLoader {
    pub base: PathBuf,
}

impl SourceLoader for FsLoader {
    fn load(&self, target: &str) -> Result<String, String> {
        // Includes are resolved relative to the including file, and are not
        // allowed to escape the policy directory: a policy that can pull in
        // `../../etc/shadow` is a file-disclosure primitive wearing a config
        // file's clothes.
        if Path::new(target).is_absolute() || target.split(['/', '\\']).any(|c| c == "..") {
            return Err(format!(
                "`{target}` escapes the policy directory; includes must be relative paths \
                 without `..`"
            ));
        }
        let path = self.base.join(target);
        std::fs::read_to_string(&path).map_err(|e| format!("{}: {e}", path.display()))
    }
}

/// The full pipeline.
pub fn compile_with_loader(
    name: &str,
    text: &str,
    opts: &CompileOptions,
    loader: &dyn SourceLoader,
) -> Compilation {
    let source = SourceFile::new(name, text);
    let mut diagnostics = Diagnostics::new();

    // --- lex -------------------------------------------------------------
    let (tokens, lex_diags) = lexer::tokenize(text);
    diagnostics.extend(lex_diags);

    // --- parse -----------------------------------------------------------
    let (mut doc, parse_diags) = parser::parse(&tokens);
    diagnostics.extend(parse_diags);

    // --- resolve includes ------------------------------------------------
    let mut visited = HashSet::new();
    visited.insert(name.to_string());
    resolve_includes(&mut doc, loader, &mut visited, &mut diagnostics, 0);

    // A document the parser could not make sense of cannot be analyzed: the
    // analyzer would report cascading nonsense on top of the real errors.
    if diagnostics.has_errors() {
        diagnostics.sort();
        return Compilation {
            source,
            policy: None,
            artifacts: Vec::new(),
            diagnostics,
            optimization: OptimizationReport::default(),
            equivalence: None,
        };
    }

    // --- semantic analysis ------------------------------------------------
    let outcome = semantic::analyze(&doc, name);
    diagnostics.extend(outcome.diagnostics);
    let Some(mut policy) = outcome.value else {
        diagnostics.sort();
        return Compilation {
            source,
            policy: None,
            artifacts: Vec::new(),
            diagnostics,
            optimization: OptimizationReport::default(),
            equivalence: None,
        };
    };

    // --- optimize ---------------------------------------------------------
    let optimization = optimizer::optimize(&mut policy, &opts.optimizer);
    diagnostics.extend(optimization.diagnostics.clone());

    // --- code generation --------------------------------------------------
    let artifacts: Vec<Artifact> = opts
        .platforms
        .iter()
        .map(|p| compiler::compile_for(*p, &policy))
        .collect();
    for a in &artifacts {
        diagnostics.extend(a.notes.clone());
    }

    // --- equivalence ------------------------------------------------------
    let equivalence = if opts.verify_equivalence && opts.platforms.len() == Platform::ALL.len() {
        let scenarios = compiler::default_scenarios(&policy);
        let models: Vec<_> = artifacts.iter().map(|a| a.model.clone()).collect();
        let report = compiler::verify_models(&policy, &models, &scenarios);
        if !report.is_equivalent() {
            diagnostics.push(
                Diagnostic::error(
                    codes::INTERNAL_EQUIVALENCE_FAILURE,
                    Span::default(),
                    format!(
                        "cross-platform equivalence check failed on {} of {} scenarios",
                        report.divergences.len(),
                        report.scenarios_checked
                    ),
                )
                .with_help("this is a compiler bug, not a policy bug; please report it"),
            );
        }
        Some(report)
    } else {
        None
    };

    if opts.deny_warnings && diagnostics.warning_count() > 0 {
        let n = diagnostics.warning_count();
        diagnostics.push(Diagnostic::error(
            codes::WARNINGS_DENIED,
            Span::default(),
            format!("{n} warning(s) treated as errors (--deny-warnings)"),
        ));
    }

    diagnostics.sort();
    let failed = diagnostics.has_errors();

    Compilation {
        source,
        policy: if failed { None } else { Some(policy) },
        artifacts: if failed { Vec::new() } else { artifacts },
        diagnostics,
        optimization,
        equivalence,
    }
}

/// Verify equivalence for an already-compiled policy, using a caller-supplied
/// scenario corpus.
pub fn verify(policy: &CompiledPolicy, scenarios: &[Scenario]) -> EquivalenceReport {
    compiler::verify_equivalence(policy, scenarios)
}

/// Maximum include nesting depth. Deep enough for a realistic
/// base -> environment -> host layering, shallow enough that a mistake is
/// reported rather than explored.
const MAX_INCLUDE_DEPTH: usize = 8;

fn resolve_includes(
    doc: &mut ast::PolicyDocument,
    loader: &dyn SourceLoader,
    visited: &mut HashSet<String>,
    diagnostics: &mut Diagnostics,
    depth: usize,
) {
    let includes = std::mem::take(&mut doc.includes);
    if includes.is_empty() {
        return;
    }
    if depth >= MAX_INCLUDE_DEPTH {
        let span = includes[0].span;
        diagnostics.push(
            Diagnostic::error(
                codes::CYCLIC_REFERENCE,
                span,
                format!("include nesting deeper than {MAX_INCLUDE_DEPTH} levels"),
            )
            .with_help("flatten the include chain"),
        );
        return;
    }

    for target in includes {
        if !visited.insert(target.value.clone()) {
            diagnostics.push(
                Diagnostic::error(
                    codes::CYCLIC_REFERENCE,
                    target.span,
                    format!("`{}` is included more than once", target.value),
                )
                .with_help("each policy may be included once; check for an include cycle"),
            );
            continue;
        }
        let text = match loader.load(&target.value) {
            Ok(t) => t,
            Err(e) => {
                diagnostics.push(Diagnostic::error(
                    codes::UNRESOLVED_REFERENCE,
                    target.span,
                    format!("cannot include `{}`: {e}", target.value),
                ));
                continue;
            }
        };
        let (tokens, lex_diags) = lexer::tokenize(&text);
        // Spans from an included file point into a different text, so they
        // cannot be rendered against this source. Report them against the
        // `include:` line instead, which is where the operator can act, and
        // carry the original line number in the message.
        for d in lex_diags {
            diagnostics.push(Diagnostic::error(
                d.code,
                target.span,
                format!(
                    "in included `{}` at line {}: {}",
                    target.value, d.span.line, d.message
                ),
            ));
        }
        let (mut included, parse_diags) = parser::parse(&tokens);
        for d in parse_diags {
            diagnostics.push(Diagnostic::error(
                d.code,
                target.span,
                format!(
                    "in included `{}` at line {}: {}",
                    target.value, d.span.line, d.message
                ),
            ));
        }
        resolve_includes(&mut included, loader, visited, diagnostics, depth + 1);
        merge_document(doc, included, &target.value, diagnostics, target.span);
    }
}

/// Merge an included document into the including one.
///
/// Definitions are additive; a name defined in both places is a duplicate and
/// is reported by the semantic analyzer, which has better spans for it. Scalar
/// settings (`version`, `metadata`, `defaults`, `network_profile`) belong to
/// the *including* document: an include is a library of definitions and rules,
/// not a way to silently retarget the policy it is pulled into.
fn merge_document(
    into: &mut ast::PolicyDocument,
    mut from: ast::PolicyDocument,
    origin: &str,
    diagnostics: &mut Diagnostics,
    at: Span,
) {
    // Spans in `from` index the fragment's text, not the text the renderer
    // will have. Retarget them to the `include:` line before anything can
    // report against them.
    ast::retarget_spans(&mut from, at);

    into.included_definitions.extend(
        from.address_groups
            .iter()
            .map(|g| g.name.value.clone())
            .chain(from.port_groups.iter().map(|g| g.name.value.clone()))
            .chain(from.signature_groups.iter().map(|g| g.name.value.clone()))
            .chain(from.applications.iter().map(|a| a.name.value.clone())),
    );
    into.included_definitions.extend(from.included_definitions);

    into.address_groups.extend(from.address_groups);
    into.port_groups.extend(from.port_groups);
    into.signature_groups.extend(from.signature_groups);
    into.applications.extend(from.applications);

    // Included rules come first so the including policy's own rules can be
    // placed ahead of them with an explicit `priority:`. Ordering within a
    // stage is by priority regardless, so this only decides ties.
    let mut rules = from.rules;
    rules.append(&mut into.rules);
    into.rules = rules;

    if from.defaults.is_some() || from.network_profile.is_some() {
        diagnostics.push(
            Diagnostic::warning(
                codes::IGNORED_INCLUDE_SETTING,
                at,
                format!(
                    "`{origin}` sets `defaults:` or `network_profile:`; those belong to the \
                     including policy and were ignored"
                ),
            )
            .with_help("keep includes to definitions and rules"),
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    struct MapLoader(HashMap<String, String>);

    impl SourceLoader for MapLoader {
        fn load(&self, target: &str) -> Result<String, String> {
            self.0
                .get(target)
                .cloned()
                .ok_or_else(|| format!("no such policy `{target}`"))
        }
    }

    const GOOD: &str = r#"
version: 1
metadata:
  name: baseline
defaults:
  action: deny
address_groups:
  dns: [1.1.1.1/32, 8.8.8.8/32]
rules:
  - id: allow-dns
    priority: 100
    action: allow
    protocol: udp
    destination:
      addresses: [dns]
      ports: [53]
  - id: block-telnet
    priority: 50
    action: deny
    protocol: tcp
    destination:
      ports: [23]
"#;

    #[test]
    fn end_to_end_compilation_succeeds() {
        let r = compile_str("t", GOOD, &CompileOptions::default());
        assert!(r.is_ok(), "{}", r.render());
        let policy = r.policy.as_ref().unwrap();
        assert_eq!(policy.rules.len(), 2);
        assert_eq!(r.artifacts.len(), 3);
        assert!(r.equivalence.as_ref().unwrap().is_equivalent());
        assert!(policy.verify_hash());
    }

    #[test]
    fn every_backend_emits_at_least_one_file() {
        let r = compile_str("t", GOOD, &CompileOptions::default());
        for platform in Platform::ALL {
            let a = r.artifact(platform).expect("artifact");
            assert!(!a.files.is_empty());
        }
    }

    #[test]
    fn errors_stop_code_generation_but_still_report() {
        let r = compile_str(
            "t",
            "version: 1\nrules:\n  - id: a\n",
            &CompileOptions::default(),
        );
        assert!(!r.is_ok());
        assert!(r.artifacts.is_empty());
        assert!(r.diagnostics.has_code(codes::MISSING_FIELD));
        assert!(r.render().contains("E0201"));
    }

    #[test]
    fn several_semantic_errors_are_reported_from_one_run() {
        let src = "version: 1\nrules:\n  - id: a\n    action: nope\n    protocol: zzz\n";
        let r = compile_str("t", src, &CompileOptions::default());
        assert!(r.diagnostics.error_count() >= 2);
    }

    #[test]
    fn deny_warnings_turns_a_clean_compile_into_a_failure() {
        let src = "version: 1\ndefaults:\n  action: deny\nrules:\n  - id: a\n    action: allow\n";
        let lenient = compile_str("t", src, &CompileOptions::default());
        assert!(lenient.is_ok());
        assert!(lenient.diagnostics.warning_count() > 0);

        let strict = compile_str(
            "t",
            src,
            &CompileOptions { deny_warnings: true, ..Default::default() },
        );
        assert!(!strict.is_ok());
        assert!(strict.diagnostics.has_code(codes::WARNINGS_DENIED));
    }

    #[test]
    fn single_platform_compilation_skips_the_equivalence_check() {
        let r = compile_str("t", GOOD, &CompileOptions::single_platform(Platform::Linux));
        assert!(r.is_ok());
        assert_eq!(r.artifacts.len(), 1);
        assert!(r.equivalence.is_none());
    }

    #[test]
    fn includes_merge_definitions_and_rules() {
        let mut map = HashMap::new();
        map.insert(
            "base.yaml".to_string(),
            "version: 1\naddress_groups:\n  corp: [10.0.0.0/8]\n\
             rules:\n  - id: from-base\n    priority: 10\n    action: deny\n    protocol: tcp\n\
             \x20   destination:\n      ports: [23]\n"
                .to_string(),
        );
        let src = "version: 1\ndefaults:\n  action: deny\ninclude: [base.yaml]\n\
                   rules:\n  - id: local\n    priority: 20\n    action: allow\n    protocol: tcp\n\
                   \x20   destination:\n      addresses: [corp]\n";
        let r = compile_with_loader("t", src, &CompileOptions::default(), &MapLoader(map));
        assert!(r.is_ok(), "{}", r.render());
        let policy = r.policy.unwrap();
        assert_eq!(policy.rules.len(), 2);
        assert!(policy.rules.iter().any(|x| x.name == "from-base"));
        // The include's address group resolved in the including policy.
        let local = policy.rules.iter().find(|x| x.name == "local").unwrap();
        assert_eq!(local.dest.cidrs.len(), 1);
    }

    #[test]
    fn diagnostics_about_included_content_point_inside_the_file_being_compiled() {
        // A span indexes one file's text. Before this was fixed, a diagnostic
        // about an included definition kept the fragment's byte offsets and
        // rendered a caret over whatever happened to sit at that offset in
        // the *including* file — a confident, wrong answer to "where?".
        let mut map = HashMap::new();
        map.insert(
            "lib.yaml".to_string(),
            // Long enough that the fragment's offsets run past the end of the
            // short including file, which is what made the bug visible.
            format!(
                "# {}\nversion: 1\naddress_groups:\n  wide: [10.0.0.0/8]\n",
                "x".repeat(400)
            ),
        );
        let src = "version: 1\ndefaults:\n  action: deny\ninclude: [lib.yaml]\n\
                   rules:\n  - id: local\n    priority: 20\n    action: allow\n    protocol: tcp\n\
                   \x20   destination:\n      addresses: [wide]\n";
        let r = compile_with_loader("t", src, &CompileOptions::default(), &MapLoader(map));
        assert!(r.is_ok(), "{}", r.render());
        for d in r.diagnostics.iter() {
            assert!(
                d.span.end as usize <= src.len(),
                "{} points at {}..{}, past the end of a {}-byte file",
                d.code,
                d.span.start,
                d.span.end,
                src.len()
            );
        }
    }

    #[test]
    fn an_unused_definition_from_an_include_is_not_reported() {
        // A shared fragment defines more than any one consumer uses. Warning
        // about that would push every consumer to fork the fragment.
        let mut map = HashMap::new();
        map.insert(
            "lib.yaml".to_string(),
            "version: 1\naddress_groups:\n  used: [10.0.0.0/8]\n  spare: [192.168.0.0/16]\n"
                .to_string(),
        );
        let src = "version: 1\ndefaults:\n  action: deny\ninclude: [lib.yaml]\n\
                   address_groups:\n  local_spare: [172.16.0.0/12]\n\
                   rules:\n  - id: local\n    priority: 20\n    action: allow\n    protocol: tcp\n\
                   \x20   destination:\n      addresses: [used]\n";
        let r = compile_with_loader("t", src, &CompileOptions::default(), &MapLoader(map));
        let text = r.render();
        assert!(!text.contains("`spare`"), "included definitions are a library:\n{text}");
        // But one the policy itself declares and never uses is still dead weight.
        assert!(text.contains("`local_spare`"), "{text}");
    }

    #[test]
    fn include_cycles_are_reported() {
        let mut map = HashMap::new();
        map.insert("a.yaml".to_string(), "version: 1\ninclude: [b.yaml]\n".to_string());
        map.insert("b.yaml".to_string(), "version: 1\ninclude: [a.yaml]\n".to_string());
        let r = compile_with_loader(
            "t",
            "version: 1\ninclude: [a.yaml]\n",
            &CompileOptions::default(),
            &MapLoader(map),
        );
        assert!(r.diagnostics.has_code(codes::CYCLIC_REFERENCE));
    }

    #[test]
    fn missing_include_is_reported_against_the_include_line() {
        let r = compile_with_loader(
            "t",
            "version: 1\ninclude: [nope.yaml]\n",
            &CompileOptions::default(),
            &MapLoader(HashMap::new()),
        );
        assert!(r.diagnostics.has_code(codes::UNRESOLVED_REFERENCE));
        let d = r
            .diagnostics
            .iter()
            .find(|d| d.code == codes::UNRESOLVED_REFERENCE)
            .unwrap();
        assert_eq!(d.span.line, 2);
    }

    #[test]
    fn includes_cannot_escape_the_policy_directory() {
        let loader = FsLoader { base: PathBuf::from("/etc/unified-firewall/policies") };
        assert!(loader.load("../../etc/shadow").is_err());
        assert!(loader.load("/etc/shadow").is_err());
        assert!(loader.load(r"..\..\windows\system32\config\sam").is_err());
    }

    #[test]
    fn included_defaults_are_ignored_with_a_warning() {
        let mut map = HashMap::new();
        map.insert(
            "base.yaml".to_string(),
            "version: 1\ndefaults:\n  action: allow\n".to_string(),
        );
        let r = compile_with_loader(
            "t",
            "version: 1\ndefaults:\n  action: deny\ninclude: [base.yaml]\n\
             rules:\n  - id: a\n    action: deny\n    protocol: tcp\n",
            &CompileOptions::default(),
            &MapLoader(map),
        );
        assert!(r.is_ok(), "{}", r.render());
        assert!(r.diagnostics.has_code(codes::IGNORED_INCLUDE_SETTING));
        assert_eq!(
            r.policy.unwrap().default_action,
            ufw_shared::policy_types::Decision::Deny
        );
    }

    #[test]
    fn no_includes_loader_explains_itself() {
        let r = compile_str("t", "version: 1\ninclude: [x.yaml]\n", &CompileOptions::default());
        assert!(r.diagnostics.has_code(codes::UNRESOLVED_REFERENCE));
        assert!(r.render().contains("filesystem context"));
    }

    #[test]
    fn optimization_report_reaches_the_caller() {
        let src = "version: 1\ndefaults:\n  action: deny\n\
                   rules:\n  - id: wide\n    priority: 10\n    action: allow\n    protocol: tcp\n\
                   \x20 - id: narrow\n    priority: 20\n    action: allow\n    protocol: tcp\n\
                   \x20   destination: 8.8.8.8/32\n";
        let r = compile_str("t", src, &CompileOptions::default());
        assert!(r.is_ok(), "{}", r.render());
        assert_eq!(r.optimization.removed_unreachable.len(), 1);
        assert!(r.diagnostics.has_code(codes::UNREACHABLE_RULE));
    }

    #[test]
    fn compiling_the_same_source_twice_is_deterministic() {
        let a = compile_str("t", GOOD, &CompileOptions::default());
        let b = compile_str("t", GOOD, &CompileOptions::default());
        assert_eq!(
            a.policy.as_ref().unwrap().ruleset_hash,
            b.policy.as_ref().unwrap().ruleset_hash
        );
        for platform in Platform::ALL {
            assert_eq!(
                a.artifact(platform).unwrap().files,
                b.artifact(platform).unwrap().files,
                "{platform} artifacts differ between runs"
            );
        }
    }
}
