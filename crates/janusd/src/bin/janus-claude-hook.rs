//! Claude Code hook adapter for Janus approved-use execution.

#![forbid(unsafe_code)]

#[path = "../claude_hook.rs"]
mod claude_hook;

fn main() {
    claude_hook::main_entry();
}
