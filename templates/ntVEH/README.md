# ntVEH Template - Vectored Exception Handler Injection

**Based on Maldev Academy Module 158: Manipulating VEH For Local Code Execution**

## 📋 Overview

This template provides **Vectored Exception Handler (VEH)** manipulation capabilities for RustPacker, allowing code injection and execution hijacking while properly handling modern Windows security features like **Control Flow Guard (CFG)**.

## 🎯 Features

| Feature | Description |
|---------|-------------|
| **VEH Manipulation** | Add, remove, and overwrite Vectored Exception Handlers |
| **CFG Bypass** | Full support for Control Flow Guard enabled processes |
| **Pointer Encoding** | Windows-compatible pointer obfuscation using Process Cookie |
| **Memory Protection** | Safe memory protection changes (Read-Only → Read-Write) |
| **Thread Safety** | Proper SRW lock handling for concurrent access |
| **Pattern Matching** | Robust internal function resolution via byte pattern matching |

## 🏗️ Structure

```
templates/ntVEH/
├── Cargo.toml          # Package config with required winapi features
├── README.md           # This file
└── src/
    ├── main.rs         # Entry point with shellcode injection demo
    ├── cfg.rs          # CFG and process cookie utilities
    ├── memory.rs       # Memory protection utilities
    └── veh.rs          # VEH/VCH manipulation core
```

## 📦 Modules

### `cfg.rs` - Control Flow Guard Utilities

- **`is_cfg_enabled()`** - Checks if CFG is active for the current process
- **`get_process_cookie()`** - Retrieves the per-process cookie value
- **`encode_pointer()`** / **`decode_pointer()`** - Windows-compatible pointer obfuscation
- **`get_ref_counter()`** - Provides global reference counter for VEH entries

### `memory.rs` - Memory Protection Utilities

- **`MemoryProtection`** - Enum for Windows memory protection flags
- **`set_memory_protection()`** - Changes memory region protection
- **`heap_alloc()`** / **`heap_free()`** - Heap memory management
- **`query_memory()`** - Queries memory region information

### `veh.rs` - Vectored Exception Handler Core

- **`VectoredHandlerEntry`** / **`VectoredHandlerList`** - Windows structure definitions
- **`get_vectored_handler_list()`** - Locates LdrpVectorHandlerList via pattern matching
- **`get_ldr_protect_mrdata()`** - Resolves LdrProtectMrdata function address
- **`get_ldrp_mrdata_heap()`** - Locates LdrpMrdataHeap for CFG-enabled processes
- **`add_veh_handler()`** - Adds a custom VEH to the handler list
- **`overwrite_first_veh()`** - Overwrites the first VEH (simpler but riskier)
- **`trigger_exception()`** - Generates a test exception to trigger handlers

### `main.rs` - Entry Point

- Integrates with RustPacker's placeholder system
- Demonstrates shellcode injection via VEH
- Uses obfuscated API calls (via `{{OBF_*}}` placeholders)
- Compatible with sandbox detection and encryption

## 🚀 Usage

### Basic VEH Injection

```rust
use veh::{add_veh_handler, trigger_exception};

// Define your exception handler
extern "system" fn my_handler(exception_info: *mut EXCEPTION_POINTERS) -> i32 {
    // Handle exception or execute payload
    EXCEPTION_EXECUTE_HANDLER
}

// Add the handler
if let Some(entry) = add_veh_handler(my_handler, true) {
    println!("VEH added at: {:p}", entry);
    
    // Trigger an exception to test
    trigger_exception();
}
```

### Shellcode Injection via VEH

The template includes a complete example in `main.rs` that:
1. Allocates memory for shellcode
2. Writes and encrypts the shellcode
3. Changes memory protection to RX
4. Adds a VEH handler
5. Triggers an exception to execute the payload

### CFG-Aware Operations

The template automatically detects CFG and adapts:
- Uses `LdrpMrdataHeap` when CFG is enabled
- Encodes pointers with the process cookie
- Handles memory protection changes safely

## 🔧 Technical Details

### Pattern Matching

The template locates internal Windows structures by searching for specific byte patterns:

- **LdrpVectorHandlerList**: `lea r12, [displacement]` (`0x4c 0x8d 0x25`)
- **LdrpMrdataHeap**: `mov rcx, [displacement]` (`0x48 0x8B 0x0D`)
- **LdrProtectMrdata**: `call [offset]` (`0xE8`)

### Pointer Encoding

Windows uses a per-process cookie to obfuscate pointers in structures like `VECTORED_HANDLER_ENTRY`:

```
encoded = RotateLeft64(raw ^ cookie, 0x40 - (cookie & 0x3f))
decoded = RotateRight64(encoded, 0x40 - (cookie & 0x3f)) ^ cookie
```

### Process Cookie

The cookie is a random value generated at process start, retrieved via:
```
NtQueryInformationProcess(..., ProcessCookie, ...)
```

### VEH List Structure

The `LdrpVectorHandlerList` contains two doubly-linked lists:
- **VEH List**: Vectored Exception Handlers (executed first)
- **VCH List**: Vectored Continue Handlers (executed after VEH)

Each entry (`VECTORED_HANDLER_ENTRY`) contains:
- Forward/backward links (LIST_ENTRY)
- Reference counter (must be 1)
- Encoded handler pointer

## ⚠️ Important Notes

### Security Considerations

1. **Thread Safety**: Always acquire SRW locks before modifying handler lists
2. **Memory Protection**: Restore original protection after modifications
3. **Handler Order**: VEH handlers are called in registration order (first registered = first called)
4. **EDR Impact**: Overwriting existing handlers may break EDR functionality

### Limitations

1. **CFG Enforcement**: Some operations may fail if CFG is strictly enforced
2. **Windows Version**: Pattern matching may need updates for new Windows versions
3. **64-bit Only**: Currently designed for x64 architectures

### Best Practices

1. **Use `add_veh_handler()`** for clean handler addition
2. **Avoid `overwrite_first_veh()`** unless you understand the existing handler's purpose
3. **Always check CFG status** before memory operations
4. **Restore memory protections** to avoid detection
5. **Handle errors gracefully** to avoid crashes

## 📚 Resources

- [Maldev Academy Module 158: Manipulating VEH For Local Code Execution](https://maldevacademy.com)
- [Exception Junction: Where All Exceptions Meet Their Handler](https://www.apriorit.com)
- [You just got vectored: Using VEH for Defense Evasion](https://www.ired.team)
- [Control Flow Guard Documentation](https://learn.microsoft.com/en-us/windows/security/threat-protection/control-flow-guard)

## 🔍 Testing

The template is designed to work with RustPacker's build system:

```bash
# Build with RustPacker
cargo run -- --template ntVEH --shellcode payload.bin --output loader.exe
```

## 📝 Changelog

- **0.1.0** - Initial implementation based on Maldev Academy Module 158
  - VEH/VCH manipulation
  - CFG bypass support
  - Pointer encoding/decoding
  - Memory protection utilities
