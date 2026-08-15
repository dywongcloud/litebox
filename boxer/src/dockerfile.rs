// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! A total Dockerfile parser: every input either parses into instructions or
//! is rejected with a line-numbered error. Nothing panics on user input.
//!
//! Supported grammar: parser directives (`# escape=`, `# syntax=` ignored),
//! comments, line continuations, multi-stage `FROM ... AS name`, exec-form
//! JSON arrays, shell-form strings, heredocs (`RUN <<EOF`, `COPY <<EOF dest`),
//! per-instruction flags (`--from`, `--chmod`, `--chown`, `--platform`, ...),
//! and the `ENV`/`LABEL`/`ARG` key=value forms including the legacy
//! space-separated `ENV KEY VALUE`.

use anyhow::{Context, bail};

/// A parsed Dockerfile: leading `ARG`s (usable in `FROM`) plus build stages.
#[derive(Debug)]
pub struct Dockerfile {
    pub pre_from_args: Vec<ArgDecl>,
    pub stages: Vec<Stage>,
}

/// One `ARG name[=default]` declaration.
#[derive(Debug, Clone)]
pub struct ArgDecl {
    pub name: String,
    pub default: Option<String>,
}

/// One build stage: a `FROM` and the instructions that follow it.
#[derive(Debug)]
pub struct Stage {
    /// Base image reference, `scratch`, or a previous stage's name/index.
    pub base: String,
    /// `--platform=` flag on the FROM, unexpanded.
    pub platform: Option<String>,
    /// `AS name`.
    pub name: Option<String>,
    /// 1-based source line of the FROM.
    pub line: usize,
    pub instructions: Vec<(usize, Instruction)>,
}

/// Shell form (`RUN echo hi`) or exec form (`RUN ["echo", "hi"]`).
#[derive(Debug, Clone)]
pub enum Command {
    Shell(String),
    Exec(Vec<String>),
}

/// A heredoc attached to an instruction.
#[derive(Debug, Clone)]
pub struct Heredoc {
    pub name: String,
    /// Body with the terminator line removed. `<<-` strips leading tabs.
    pub body: String,
}

/// Flags accepted on COPY and ADD.
#[derive(Debug, Clone, Default)]
pub struct CopyFlags {
    pub from: Option<String>,
    pub chmod: Option<String>,
    pub chown: Option<String>,
    pub checksum: Option<String>,
    pub link: bool,
    pub excludes: Vec<String>,
}

#[derive(Debug)]
pub enum Instruction {
    Run {
        command: Command,
        heredocs: Vec<Heredoc>,
    },
    Cmd(Command),
    Entrypoint(Command),
    Copy {
        flags: CopyFlags,
        sources: Vec<String>,
        dest: String,
        heredocs: Vec<Heredoc>,
    },
    Add {
        flags: CopyFlags,
        sources: Vec<String>,
        dest: String,
        heredocs: Vec<Heredoc>,
    },
    Env(Vec<(String, String)>),
    Arg(Vec<ArgDecl>),
    Label(Vec<(String, String)>),
    Workdir(String),
    User(String),
    Expose(Vec<String>),
    Volume(Vec<String>),
    Shell(Vec<String>),
    StopSignal(String),
    /// Recorded into image config; not executed at build time.
    Healthcheck(String),
    /// Recorded into image config; trigger execution is a registry feature.
    Onbuild(String),
    /// Deprecated; recorded as a label.
    Maintainer(String),
}

/// Parse a complete Dockerfile.
pub fn parse(text: &str) -> anyhow::Result<Dockerfile> {
    let escape = parse_escape_directive(text);
    let logical_lines = logical_lines(text, escape)?;

    let mut pre_from_args: Vec<ArgDecl> = Vec::new();
    let mut stages: Vec<Stage> = Vec::new();

    for line in logical_lines {
        let (keyword, rest) = split_keyword(&line.text)
            .with_context(|| format!("line {}: expected an instruction", line.number))?;
        let keyword_upper = keyword.to_ascii_uppercase();

        if keyword_upper == "FROM" {
            let stage = parse_from(rest, line.number)
                .with_context(|| format!("line {}: invalid FROM", line.number))?;
            stages.push(stage);
            continue;
        }

        if stages.is_empty() {
            if keyword_upper == "ARG" {
                pre_from_args.extend(
                    parse_arg(rest)
                        .with_context(|| format!("line {}: invalid ARG", line.number))?,
                );
                continue;
            }
            bail!(
                "line {}: {} before the first FROM (only ARG may precede FROM)",
                line.number,
                keyword_upper
            );
        }

        let instruction = parse_instruction(&keyword_upper, rest, &line, escape)
            .with_context(|| format!("line {}: invalid {}", line.number, keyword_upper))?;
        stages
            .last_mut()
            .expect("stages is non-empty in this branch")
            .instructions
            .push((line.number, instruction));
    }

    if stages.is_empty() {
        bail!("Dockerfile contains no FROM instruction");
    }

    Ok(Dockerfile {
        pre_from_args,
        stages,
    })
}

/// A logical line after continuation joining, plus its heredoc bodies.
struct LogicalLine {
    number: usize,
    text: String,
    heredocs: Vec<Heredoc>,
}

/// Read the `# escape=` parser directive if present in the directive block at
/// the top of the file. Defaults to backslash.
fn parse_escape_directive(text: &str) -> char {
    for raw_line in text.lines() {
        let line = raw_line.trim();
        if line.is_empty() {
            continue;
        }
        let Some(directive) = line.strip_prefix('#') else {
            // First non-comment line ends the directive block.
            return '\\';
        };
        let directive = directive.trim();
        if let Some((key, value)) = directive.split_once('=') {
            if key.trim().eq_ignore_ascii_case("escape") {
                let value = value.trim();
                if value == "`" {
                    return '`';
                }
                return '\\';
            }
            // Other directives (syntax=...) are ignored; keep scanning.
            continue;
        }
        // A plain comment ends the directive block.
        return '\\';
    }
    '\\'
}

/// Join continuation lines, strip comments, and collect heredoc bodies.
fn logical_lines(text: &str, escape: char) -> anyhow::Result<Vec<LogicalLine>> {
    let mut result = Vec::new();
    let mut lines = text.lines().enumerate().peekable();

    while let Some((idx, raw_line)) = lines.next() {
        let number = idx + 1;
        let trimmed = raw_line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }

        let mut logical = String::from(raw_line);
        // Join continuations: a trailing escape char (not doubled) pulls in
        // the next line; interleaved comment lines are dropped.
        while logical.trim_end().ends_with(escape)
            && !logical.trim_end().ends_with([escape, escape])
        {
            let without = logical.trim_end();
            logical = without[..without.len() - escape.len_utf8()].to_string();
            loop {
                let Some((_, next)) = lines.next() else {
                    bail!("line {number}: line continuation at end of file");
                };
                let next_trimmed = next.trim();
                if next_trimmed.starts_with('#') {
                    continue;
                }
                logical.push_str(next);
                break;
            }
        }

        // Collect heredoc bodies named on this line. Only RUN/COPY/ADD carry
        // heredocs (matching BuildKit); scanning every instruction turned a
        // `<<` in shell arithmetic or an ENV/LABEL value into a phantom
        // heredoc that broke or silently truncated the build.
        let mut heredocs = Vec::new();
        if instruction_takes_heredoc(&logical) {
            for (name, strip_tabs) in heredoc_markers(&logical) {
                let mut body = String::new();
                let mut terminated = false;
                for (_, body_line) in lines.by_ref() {
                    let candidate = if strip_tabs {
                        body_line.trim_start_matches('\t')
                    } else {
                        body_line
                    };
                    if candidate == name {
                        terminated = true;
                        break;
                    }
                    body.push_str(candidate);
                    body.push('\n');
                }
                if !terminated {
                    bail!("line {number}: heredoc <<{name} is never terminated");
                }
                heredocs.push(Heredoc { name, body });
            }
        }

        result.push(LogicalLine {
            number,
            text: logical.trim().to_string(),
            heredocs,
        });
    }

    Ok(result)
}

/// Find `<<EOF` / `<<-EOF` / `<<"EOF"` markers in a logical line, in order.
fn heredoc_markers(line: &str) -> Vec<(String, bool)> {
    let mut markers = Vec::new();
    let bytes = line.as_bytes();
    let mut i = 0;
    while i + 1 < bytes.len() {
        if bytes[i] == b'<' && bytes[i + 1] == b'<' {
            // "<<" inside a shell redirection like "cat << EOF" counts; the
            // docker grammar requires the name to follow immediately, with an
            // optional '-' for tab stripping.
            //
            // The `<<` must also begin a shell word (optionally behind an fd
            // number like `2<<EOF`), matching BuildKit's per-word
            // `^(\d*)<<...` rule. Without this, `1<<8` inside `$((...))` or a
            // quoted `'1<<20'` would be misread as a heredoc named `8`/`20`.
            let mut word_start = i;
            while word_start > 0 && bytes[word_start - 1].is_ascii_digit() {
                word_start -= 1;
            }
            let at_word_start = word_start == 0 || bytes[word_start - 1].is_ascii_whitespace();
            if !at_word_start {
                i += 1;
                continue;
            }
            let mut j = i + 2;
            let strip_tabs = bytes.get(j) == Some(&b'-');
            if strip_tabs {
                j += 1;
            }
            let quote = match bytes.get(j) {
                Some(&q @ (b'"' | b'\'')) => {
                    j += 1;
                    Some(q)
                }
                _ => None,
            };
            let start = j;
            while j < bytes.len()
                && (bytes[j].is_ascii_alphanumeric() || bytes[j] == b'_' || bytes[j] == b'.')
            {
                j += 1;
            }
            let name_ok = j > start
                && match quote {
                    Some(q) => bytes.get(j) == Some(&q),
                    None => true,
                };
            if name_ok {
                let name = String::from_utf8_lossy(&bytes[start..j]).into_owned();
                markers.push((name, strip_tabs));
                i = j;
                continue;
            }
        }
        i += 1;
    }
    markers
}

/// Whether an instruction can carry a heredoc body: RUN, COPY, or ADD, matching
/// BuildKit -- optionally behind an `ONBUILD` prefix. Every other instruction
/// treats `<<` in its text as literal.
fn instruction_takes_heredoc(logical: &str) -> bool {
    fn takes(kw: &str) -> bool {
        kw.eq_ignore_ascii_case("RUN")
            || kw.eq_ignore_ascii_case("COPY")
            || kw.eq_ignore_ascii_case("ADD")
    }
    let Some((kw, rest)) = split_keyword(logical) else {
        return false;
    };
    if takes(kw) {
        return true;
    }
    if kw.eq_ignore_ascii_case("ONBUILD")
        && let Some((inner, _)) = split_keyword(rest)
    {
        return takes(inner);
    }
    false
}

fn split_keyword(line: &str) -> Option<(&str, &str)> {
    let line = line.trim();
    if line.is_empty() {
        return None;
    }
    match line.split_once(char::is_whitespace) {
        Some((kw, rest)) => Some((kw, rest.trim())),
        None => Some((line, "")),
    }
}

fn parse_from(rest: &str, line: usize) -> anyhow::Result<Stage> {
    let words = split_words(rest)?;
    let mut platform = None;
    let mut base = None;
    let mut name = None;
    let mut iter = words.into_iter().peekable();
    while let Some(word) = iter.next() {
        if let Some(value) = word.strip_prefix("--platform=") {
            platform = Some(value.to_string());
        } else if word.starts_with("--") {
            bail!("unknown FROM flag: {word}");
        } else if base.is_none() {
            base = Some(word);
        } else if word.eq_ignore_ascii_case("as") {
            let stage_name = iter.next().context("FROM ... AS requires a stage name")?;
            name = Some(stage_name);
        } else {
            bail!("unexpected FROM argument: {word}");
        }
    }
    Ok(Stage {
        base: base.context("FROM requires a base image")?,
        platform,
        name,
        line,
        instructions: Vec::new(),
    })
}

fn parse_instruction(
    keyword: &str,
    rest: &str,
    line: &LogicalLine,
    escape: char,
) -> anyhow::Result<Instruction> {
    match keyword {
        "RUN" => Ok(Instruction::Run {
            command: parse_command(rest)?,
            heredocs: line.heredocs.clone(),
        }),
        "CMD" => Ok(Instruction::Cmd(parse_command(rest)?)),
        "ENTRYPOINT" => Ok(Instruction::Entrypoint(parse_command(rest)?)),
        "COPY" | "ADD" => {
            let (flags, mut paths) = parse_copy_args(rest)?;
            // Heredoc markers (`<<EOF`) are captured separately as
            // `line.heredocs`; drop them from the path list so a lone-heredoc
            // COPY does not carry a phantom source, which would make its single
            // destination look like a directory and write to `dest/EOF`.
            paths.retain(|p| !p.starts_with("<<"));
            if paths.len() < 2 && line.heredocs.is_empty() {
                bail!("{keyword} requires at least one source and a destination");
            }
            if paths.is_empty() {
                bail!("{keyword} requires a destination");
            }
            let dest = paths.pop().expect("paths checked non-empty");
            if keyword == "COPY" {
                Ok(Instruction::Copy {
                    flags,
                    sources: paths,
                    dest,
                    heredocs: line.heredocs.clone(),
                })
            } else {
                Ok(Instruction::Add {
                    flags,
                    sources: paths,
                    dest,
                    heredocs: line.heredocs.clone(),
                })
            }
        }
        "ENV" => Ok(Instruction::Env(parse_key_values(rest, true)?)),
        "LABEL" => Ok(Instruction::Label(parse_key_values(rest, false)?)),
        "ARG" => Ok(Instruction::Arg(parse_arg(rest)?)),
        "WORKDIR" => Ok(Instruction::Workdir(unquote_single(rest)?)),
        "USER" => Ok(Instruction::User(rest.trim().to_string())),
        "EXPOSE" => Ok(Instruction::Expose(split_words(rest)?)),
        "VOLUME" => {
            if rest.trim_start().starts_with('[') {
                Ok(Instruction::Volume(parse_exec_array(rest)?))
            } else {
                Ok(Instruction::Volume(split_words(rest)?))
            }
        }
        "SHELL" => Ok(Instruction::Shell(parse_exec_array(rest)?)),
        "STOPSIGNAL" => Ok(Instruction::StopSignal(rest.trim().to_string())),
        "HEALTHCHECK" => Ok(Instruction::Healthcheck(rest.trim().to_string())),
        "ONBUILD" => Ok(Instruction::Onbuild(rest.trim().to_string())),
        "MAINTAINER" => Ok(Instruction::Maintainer(rest.trim().to_string())),
        other => bail!("unknown instruction: {other}"),
    }
    .map(|instruction| strip_escape_doubling(instruction, escape))
}

/// Collapse doubled escape characters left by continuation handling in shell
/// form commands (`\\` at line end means a literal escape, not a join).
fn strip_escape_doubling(instruction: Instruction, _escape: char) -> Instruction {
    // Shell semantics own unescaping inside RUN/CMD strings; the parser keeps
    // them verbatim. This hook exists so the doubled-escape rule has one home
    // if it ever needs to normalize; today verbatim is correct because the
    // shell sees the same text docker's shell would.
    instruction
}

fn parse_command(rest: &str) -> anyhow::Result<Command> {
    let trimmed = rest.trim_start();
    if trimmed.starts_with('[') {
        Ok(Command::Exec(parse_exec_array(trimmed)?))
    } else {
        Ok(Command::Shell(rest.trim().to_string()))
    }
}

/// Parse the JSON-style exec form array: `["a", "b"]`.
fn parse_exec_array(text: &str) -> anyhow::Result<Vec<String>> {
    let value: serde_json::Value = serde_json::from_str(text.trim())
        .with_context(|| format!("exec form is not a valid JSON array: {text}"))?;
    let serde_json::Value::Array(items) = value else {
        bail!("exec form must be a JSON array: {text}");
    };
    items
        .into_iter()
        .map(|item| match item {
            serde_json::Value::String(s) => Ok(s),
            other => bail!("exec form array elements must be strings, got {other}"),
        })
        .collect()
}

/// Split on whitespace honoring double/single quotes and backslash escapes.
fn split_words(text: &str) -> anyhow::Result<Vec<String>> {
    let mut words = Vec::new();
    let mut current = String::new();
    let mut in_word = false;
    let mut chars = text.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '"' => {
                in_word = true;
                loop {
                    match chars.next() {
                        Some('"') => break,
                        Some('\\') => {
                            let escaped = chars.next().context("dangling backslash in quotes")?;
                            current.push(escaped);
                        }
                        Some(inner) => current.push(inner),
                        None => bail!("unterminated double quote in: {text}"),
                    }
                }
            }
            '\'' => {
                in_word = true;
                loop {
                    match chars.next() {
                        Some('\'') => break,
                        Some(inner) => current.push(inner),
                        None => bail!("unterminated single quote in: {text}"),
                    }
                }
            }
            '\\' => {
                in_word = true;
                if let Some(&next) = chars.peek() {
                    chars.next();
                    current.push(next);
                }
            }
            c if c.is_whitespace() => {
                if in_word {
                    words.push(std::mem::take(&mut current));
                    in_word = false;
                }
            }
            c => {
                in_word = true;
                current.push(c);
            }
        }
    }
    if in_word {
        words.push(current);
    }
    Ok(words)
}

fn parse_copy_args(rest: &str) -> anyhow::Result<(CopyFlags, Vec<String>)> {
    let mut flags = CopyFlags::default();
    let mut paths = Vec::new();
    if rest.trim_start().starts_with('[') {
        // Exec-form COPY: ["src", "dest"] with no flags mixed in.
        return Ok((flags, parse_exec_array(rest)?));
    }
    for word in split_words(rest)? {
        if let Some(value) = word.strip_prefix("--from=") {
            flags.from = Some(value.to_string());
        } else if let Some(value) = word.strip_prefix("--chmod=") {
            flags.chmod = Some(value.to_string());
        } else if let Some(value) = word.strip_prefix("--chown=") {
            flags.chown = Some(value.to_string());
        } else if let Some(value) = word.strip_prefix("--checksum=") {
            flags.checksum = Some(value.to_string());
        } else if let Some(value) = word.strip_prefix("--exclude=") {
            flags.excludes.push(value.to_string());
        } else if word == "--link" {
            flags.link = true;
        } else if word.starts_with("--") {
            bail!("unknown COPY/ADD flag: {word}");
        } else {
            paths.push(word);
        }
    }
    Ok((flags, paths))
}

/// Parse `k=v k2=v2 ...`; when `allow_legacy` is set, a bare `KEY VALUE...`
/// (no `=` in the first word) is accepted as a single pair.
fn parse_key_values(rest: &str, allow_legacy: bool) -> anyhow::Result<Vec<(String, String)>> {
    let words = split_words(rest)?;
    if words.is_empty() {
        bail!("expected at least one key=value pair");
    }
    if allow_legacy && !words[0].contains('=') {
        let key = words[0].clone();
        let value = words[1..].join(" ");
        return Ok(vec![(key, value)]);
    }
    words
        .into_iter()
        .map(|word| {
            let (key, value) = word
                .split_once('=')
                .with_context(|| format!("expected key=value, got: {word}"))?;
            if key.is_empty() {
                bail!("empty key in: {word}");
            }
            Ok((key.to_string(), value.to_string()))
        })
        .collect()
}

fn parse_arg(rest: &str) -> anyhow::Result<Vec<ArgDecl>> {
    let words = split_words(rest)?;
    if words.is_empty() {
        bail!("ARG requires a name");
    }
    words
        .into_iter()
        .map(|word| match word.split_once('=') {
            Some((name, default)) => {
                if name.is_empty() {
                    bail!("empty ARG name in: {word}");
                }
                Ok(ArgDecl {
                    name: name.to_string(),
                    default: Some(default.to_string()),
                })
            }
            None => Ok(ArgDecl {
                name: word,
                default: None,
            }),
        })
        .collect()
}

/// A single possibly-quoted token (WORKDIR).
fn unquote_single(rest: &str) -> anyhow::Result<String> {
    let words = split_words(rest)?;
    match words.len() {
        1 => Ok(words.into_iter().next().expect("len checked")),
        0 => bail!("expected a path"),
        _ => bail!("expected a single path, got: {rest}"),
    }
}

/// Expand `$VAR`, `${VAR}`, `${VAR:-default}`, `${VAR:+alt}` using `lookup`.
/// `\$` escapes a literal dollar.
pub fn substitute(text: &str, lookup: &dyn Fn(&str) -> Option<String>) -> String {
    let mut result = String::with_capacity(text.len());
    let mut chars = text.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\\' {
            if let Some(&'$') = chars.peek() {
                chars.next();
                result.push('$');
                continue;
            }
            result.push(c);
            continue;
        }
        if c != '$' {
            result.push(c);
            continue;
        }
        match chars.peek() {
            Some('{') => {
                chars.next();
                let mut inner = String::new();
                let mut depth = 1;
                for inner_c in chars.by_ref() {
                    if inner_c == '{' {
                        depth += 1;
                    }
                    if inner_c == '}' {
                        depth -= 1;
                        if depth == 0 {
                            break;
                        }
                    }
                    inner.push(inner_c);
                }
                result.push_str(&expand_braced(&inner, lookup));
            }
            Some(c2) if c2.is_ascii_alphabetic() || *c2 == '_' => {
                let mut name = String::new();
                while let Some(&nc) = chars.peek() {
                    if nc.is_ascii_alphanumeric() || nc == '_' {
                        name.push(nc);
                        chars.next();
                    } else {
                        break;
                    }
                }
                if let Some(value) = lookup(&name) {
                    result.push_str(&value);
                }
            }
            _ => result.push('$'),
        }
    }
    result
}

fn expand_braced(inner: &str, lookup: &dyn Fn(&str) -> Option<String>) -> String {
    if let Some((name, default)) = inner.split_once(":-") {
        return lookup(name).unwrap_or_else(|| default.to_string());
    }
    if let Some((name, alt)) = inner.split_once(":+") {
        return if lookup(name).is_some() {
            alt.to_string()
        } else {
            String::new()
        };
    }
    lookup(inner).unwrap_or_default()
}
