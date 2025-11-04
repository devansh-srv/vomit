use anyhow::{Context, Result};
use libbpf_rs::MapCore;
use std::collections::HashMap;
use std::fs;
use std::io::{BufRead, BufReader};

const MAX_STACK_DEPTH: usize = 20;

#[derive(Debug, Clone)]
pub struct StackFrame {
    pub address: u64,
    pub symbol: String,
    pub module: String,
    pub offset: u64,
}
#[derive(Debug, Clone)]
pub struct ResolvedStack {
    pub frames: Vec<StackFrame>,
}

pub struct StackResolver {
    symbol_cache: HashMap<(u32, u64), StackFrame>,
    kernel_symbols: HashMap<u64, (String, String)>,
}
impl StackResolver {
    fn load_kernel_symbols() -> Result<HashMap<u64, (String, String)>> {
        let mut symbols = HashMap::new();
        let file = fs::File::open("/proc/kallsyms")
            .context("Failed to open /proc/kallsyms (need root)")?;
        let reader = BufReader::new(file);
        for line in reader.lines() {
            let line = line?;
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 3 {
                if let Ok(addr) = u64::from_str_radix(parts[0], 16) {
                    let symbol = parts[2].to_string();
                    let module = if parts.len() >= 4 {
                        parts[3].trim_matches(|c| c == '[' || c == ']').to_string()
                    } else {
                        "kernel".to_string()
                    };
                    symbols.insert(addr, (symbol, module));
                }
            }
        }
        println!("Loaded {} kernel symbols", symbols.len());
        Ok(symbols)
    }
    pub fn new() -> Result<Self> {
        let kernel_symbols = Self::load_kernel_symbols()?;
        Ok(Self {
            symbol_cache: HashMap::new(),
            kernel_symbols,
        })
    }
    fn resolve_kernel_address(&self, addr: u64) -> StackFrame {
        let mut best_match: Option<(u64, &(String, String))> = None;

        for (sym_addr, sym_info) in &self.kernel_symbols {
            if *sym_addr <= addr {
                if let Some((best_addr, _)) = best_match {
                    if *sym_addr > best_addr {
                        best_match = Some((*sym_addr, sym_info));
                    }
                } else {
                    best_match = Some((*sym_addr, sym_info));
                }
            }
        }

        if let Some((sym_addr, (symbol, module))) = best_match {
            StackFrame {
                address: addr,
                symbol: symbol.clone(),
                module: module.clone(),
                offset: addr - sym_addr,
            }
        } else {
            StackFrame {
                address: addr,
                symbol: format!("0x{:x}", addr),
                module: "unknown".to_string(),
                offset: 0,
            }
        }
    }
    fn extract_symbol_name(&self, path: &str) -> String {
        path.split('/').last().unwrap_or("unknown").to_string()
    }
    // Format: address perms offset dev inode pathname
    // Example: 7f1234567000-7f1234568000 r-xp 00001000 08:01 12345 /lib/x86_64-linux-gnu/libc.so.6
    fn resolve_user_address(&self, pid: u32, addr: u64) -> StackFrame {
        let maps_path = format!("/proc/{}/maps", pid);
        if let Ok(maps) = fs::read_to_string(&maps_path) {
            for line in maps.lines() {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 6 {
                    let addr_range: Vec<&str> = parts[0].split('-').collect();
                    if addr_range.len() == 2 {
                        if let (Ok(start), Ok(end)) = (
                            u64::from_str_radix(addr_range[0], 16),
                            u64::from_str_radix(addr_range[1], 16),
                        ) {
                            if addr >= start && addr < end {
                                let module = parts[5].to_string();
                                let offset = addr - start;
                                return StackFrame {
                                    address: addr,
                                    symbol: self.extract_symbol_name(&module),
                                    module: module.clone(),
                                    offset,
                                };
                            }
                        }
                    }
                }
            }
        }
        StackFrame {
            address: addr,
            symbol: format!("0x{:x}", addr),
            module: "unknown".to_string(),
            offset: 0,
        }
    }

    pub fn resolve_kernel_stack(&mut self, addresses: &[u64]) -> ResolvedStack {
        let mut frames = Vec::new();
        for &addr in addresses {
            if addr == 0 {
                break;
            }
            let frame = self.resolve_kernel_address(addr);
            frames.push(frame);
        }
        ResolvedStack { frames }
    }
    pub fn resolve_user_stack(&mut self, pid: u32, addresses: &[u64]) -> ResolvedStack {
        let mut frames = Vec::new();
        for &addr in addresses {
            if addr == 0 {
                break;
            }
            if let Some(cached) = self.symbol_cache.get(&(pid, addr)) {
                frames.push(cached.clone());
            }
            let frame = self.resolve_kernel_address(addr);
            frames.push(frame);
        }
        ResolvedStack { frames }
    }
}

pub fn read_stack_from_map(stack_map: &libbpf_rs::Map, stack_id: i32) -> Result<Vec<u64>> {
    if stack_id < 0 {
        return Ok(Vec::new());
    }

    let key = (stack_id as u32).to_ne_bytes();
    let value = match stack_map.lookup(&key, libbpf_rs::MapFlags::ANY)? {
        Some(v) => v,
        None => return Ok(Vec::new()),
    };

    let mut addresses = Vec::new();
    for chunk in value.chunks_exact(8) {
        let addr = u64::from_ne_bytes(chunk.try_into().unwrap());
        if addr == 0 {
            break;
        }
        addresses.push(addr);
    }

    Ok(addresses)
}

impl ResolvedStack {
    pub fn to_string(&self, indent: usize) -> String {
        let indent_str = " ".repeat(indent);
        self.frames
            .iter()
            .map(|f| {
                if f.offset > 0 {
                    format!(
                        "{}→ {}+0x{:x} ({})",
                        indent_str, f.symbol, f.offset, f.module
                    )
                } else {
                    format!("{}→ {} ({})", indent_str, f.symbol, f.module)
                }
            })
            .collect::<Vec<_>>()
            .join("\n")
    }
}
