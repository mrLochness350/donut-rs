use alloc::string::String;
use alloc::vec::Vec;
use crate::errors::DonutResult;


/// Splits a given string to the format expected by the platform
pub fn split_args(cmd: &str) -> DonutResult<Vec<String>> {
    #[cfg(unix)]
    return posix_split_args(cmd);
    #[cfg(windows)]
    Ok(windows_split_args(cmd))

}

#[cfg(unix)]
fn posix_split_args(cmd: &str) -> DonutResult<Vec<String>> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let (mut in_s, mut in_d, mut esc) = (false, false, false);

    for ch in cmd.chars() {
        if esc {
            cur.push(ch);
            esc = false;
            continue;
        }
        match ch {
            '\\' if in_d || !in_s => {
                esc = true;
            }
            '"' if !in_s => {
                in_d = !in_d;
            }
            '\'' if !in_d => {
                in_s = !in_s;
            }
            c if c.is_ascii_whitespace() && !in_s && !in_d => {
                if !cur.is_empty() {
                    out.push(core::mem::take(&mut cur));
                }
            }
            _ => cur.push(ch),
        }
    }
    if esc || in_s || in_d {
        return Err(crate::errors::DonutError::ParseFailed);
    }
    if !cur.is_empty() {
        out.push(cur);
    }
    Ok(out)
}

#[cfg(windows)]
fn windows_split_args(s: &str) -> Vec<String> {
    let mut args = Vec::new();
    let mut cur = String::new();
    let mut in_quotes = false;
    let mut slashes = 0usize;

    for ch in s.chars() {
        match ch {
            '\\' => { slashes += 1; }
            '"' => {
                for _ in 0..(slashes / 2) { cur.push('\\'); }
                if slashes.is_multiple_of(2) {
                    in_quotes = !in_quotes;
                } else {
                    cur.push('"');
                }
                slashes = 0;
            }
            c if c.is_ascii_whitespace() && !in_quotes => {
                for _ in 0..slashes { cur.push('\\'); }
                slashes = 0;
                if !cur.is_empty() {
                    args.push(core::mem::take(&mut cur));
                }
            }
            c => {
                for _ in 0..slashes { cur.push('\\'); }
                slashes = 0;
                cur.push(c);
            }
        }
    }
    for _ in 0..slashes { cur.push('\\'); }
    if !cur.is_empty() { args.push(cur); }
    args
}