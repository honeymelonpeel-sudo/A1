# Nebulae_3 Lua Obfuscator

Luau (Roblox) compatible Lua obfuscator with full security checks retained.

## Supported Lua Versions

| Version | Status |
|---------|--------|
| Lua 5.1 | ✅ |
| Lua 5.2 | ✅ |
| Lua 5.4 | ✅ |
| LuaJIT | ✅ |
| Luau (Roblox) | ✅ |

## Usage

```bash
lua5.1 Nebulae_3.lua input.lua
```

Output: `Nebulae_input.lua`

## Features

- **Luau Compatibility**: VM execution (no `load`), hash backup preserved
- **Security Checks**: Gate true (VM path), load/table.concat integrity checks retained
- **Multi-Version Support**: Works across Lua 5.1/5.2/5.4/JIT/Luau
- **Multi-Pass Obfuscation**: Supports iterative obfuscation passes

## Testing

```bash
lua5.1 Nebulae_test.lua   # Single pass
lua5.2 Nebulae_test.lua   # Cross-version
luajit Nebulae_test.lua   # JIT
```

## License

Proprietary - Source code confidential
