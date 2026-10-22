# DeepPacket Native BPF Filter Plan

## Goal

Implement a focused native capture-filter compiler for Linux classic BPF.
The filter expression will be compiled in `dp/capture/bpf.cpp`, then attached
to the `AF_PACKET` socket before the capture thread starts.

This is a capture filter, not a display filter:

```text
network interface
    -> kernel BPF filter
    -> AF_PACKET socket
    -> capture thread
    -> SPSC ring buffer
    -> parser and validator
    -> summaries
```

Packets rejected by the BPF program never enter the user-space queue.

## Scope for the first version

Support a deliberately small language:

```text
tcp
udp
icmp
arp
host 192.168.1.10
port 443
tcp and port 443
host 192.168.1.10 and tcp
tcp or udp
not arp
(tcp or udp) and port 443
```

Do not claim full Wireshark or libpcap compatibility. Do not add libpcap as a
dependency. The first implementation targets classic Linux BPF using
`<linux/filter.h>`.

## Repository boundaries

### `dp/capture/bpf.hpp`

Expose only the stable public compiler contract:

- `BpfProgram`
  - owns `std::vector<sock_filter>` instructions
  - provides `empty()` and `size()`
- `BpfCompileError`
  - describes invalid syntax, values, unsupported expressions, and size limits
- `BpfCompileResult`
  - contains success state, compiled program, error enum, and readable message
- `compile_bpf(const std::string&)`

Keep the lexer, parser, AST, and code-generation helpers private to
`bpf.cpp`. Callers should not depend on the internal representation.

### `dp/capture/bpf.cpp`

Own the compiler pipeline:

```text
filter text
    -> lexer
    -> tokens
    -> recursive-descent parser
    -> private AST
    -> semantic validation
    -> BPF instruction generation
    -> BpfCompileResult
```

### `dp/capture/raw-capture.cpp`

Own socket-specific behavior:

1. Create the `AF_PACKET` socket.
2. Bind it to the requested interface.
3. Compile the supplied filter.
4. Attach the resulting program with `SO_ATTACH_FILTER`.
5. Start the capture thread only after successful attachment.

Do not put lexer/parser logic in `raw-capture.cpp`.

## Compiler stages

### 1. Define the grammar

Use this grammar:

```text
expression        := or_expression

or_expression     := and_expression
                     ("or" and_expression)*

and_expression    := unary_expression
                     ("and" unary_expression)*

unary_expression  := "not" unary_expression
                   | primary

primary           := "(" expression ")"
                   | predicate

predicate         := "tcp"
                   | "udp"
                   | "icmp"
                   | "arp"
                   | "host" IPv4_ADDRESS
                   | "port" NUMBER
```

The precedence order is:

```text
parentheses > not > and > or
```

### 2. Define tokens

Use a private token representation in `bpf.cpp`:

```cpp
enum class TokenKind {
    Identifier,
    Number,
    IPv4Address,
    And,
    Or,
    Not,
    LeftParen,
    RightParen,
    End
};
```

Each token should preserve its kind and source text. A numeric value may be
stored for number tokens after lexical conversion.

Unlike a general programming language, this filter language does not need a
traditional symbol table: it has fixed keywords and literal values, but no
user-defined identifiers or declarations. Use keyword/protocol lookup tables
instead.

### 3. Implement the lexer

The lexer should:

- skip whitespace
- recognize identifiers
- recognize decimal numbers
- recognize IPv4 address text
- recognize parentheses
- classify `and`, `or`, and `not`
- report invalid characters

The lexer should not decide whether a protocol is supported. It should emit an
identifier; the parser/semantic layer decides whether that identifier is valid.

### 4. Define a private AST

Use a predicate model:

```cpp
enum class PredicateKind {
    Protocol,
    Host,
    Port
};
```

A predicate should store:

- protocol enum for protocol predicates
- validated binary IPv4 address for host predicates
- validated `uint16_t` port for port predicates

Use expression nodes:

```cpp
enum class ExpressionKind {
    Predicate,
    And,
    Or,
    Not
};
```

The AST examples should look like:

```text
tcp and port 443

        AND
       /   \
    TCP   PORT(443)
```

Keep the AST private to `bpf.cpp`.

### 5. Implement recursive-descent parsing

Recommended parser functions:

```cpp
parse_expression()
parse_or_expression()
parse_and_expression()
parse_unary_expression()
parse_primary()
parse_predicate()
```

The structure should mirror the grammar and naturally enforce precedence:

- `parse_or_expression()` calls `parse_and_expression()`
- `parse_and_expression()` calls `parse_unary_expression()`
- `parse_unary_expression()` handles `not`
- `parse_primary()` handles parentheses and predicates

Require the `End` token after the complete expression so trailing garbage is
reported rather than ignored.

### 6. Perform semantic validation

Validate values while building the AST:

```text
host 192.168.1.10
```

- require an address after `host`
- validate four IPv4 octets
- reject values outside `0..255`
- store the address in binary form

```text
port 443
```

- require a number after `port`
- reject negative values
- reject values above `65535`
- store the result as `uint16_t`

Useful errors include:

```text
empty filter expression
expected expression after 'and'
unknown protocol 'http'
invalid IPv4 address '999.1.1.1'
expected port number after 'port'
port must be between 0 and 65535
missing closing ')'
```

For the initial language, a separate semantic-analysis pass is optional:

```text
lexer -> parser plus validation -> validated AST
```

Add a separate semantic pass only if the language grows enough to justify it.

## BPF code generation

Generate classic `sock_filter` instructions from the validated AST.

The generator must:

- inspect raw packet bytes, not construct `PacketView`
- include bounds-safe checks before variable-offset loads
- distinguish Ethernet, IPv4, IPv6, and ARP paths
- produce explicit accept and reject paths
- keep the generated program within the classic BPF instruction limit

The parser structs in `dp/parser/packet.hpp` define protocol semantics, but
they are not used as kernel-side objects. The compiler translates those
semantics into raw offset tests.

Examples:

```text
tcp
```

Conceptually:

```text
check Ethernet type
check IPv4/IPv6 protocol
accept TCP
reject everything else
```

```text
port 443
```

Conceptually:

```text
identify a supported IP packet
locate the transport header
compare source port with 443
compare destination port with 443
accept on either match
reject otherwise
```

Boolean expressions require conditional control flow:

- `AND`: the left side must succeed before evaluating the right side
- `OR`: evaluate the right side when the left side fails
- `NOT`: swap true and false outcomes

If needed, introduce an internal BPF fragment/backpatching structure for
unresolved jump targets. Do not expose it in `bpf.hpp`.

## Integration order

Implement and verify the compiler independently before touching live capture:

1. Add `bpf.hpp`.
2. Add private token and lexer types in `bpf.cpp`.
3. Add the private AST.
4. Add the recursive-descent parser.
5. Add semantic validation.
6. Generate BPF for protocol predicates.
7. Generate BPF for host and port predicates.
8. Generate BPF for boolean operators.
9. Add isolated compiler tests.
10. Add `bpf.cpp` to the `dp_engine` target in the root `CMakeLists.txt`.
11. Extend `SocketCapture` to accept an optional filter.
12. Attach the compiled program after bind and before the capture thread starts.
13. Propagate compile and attach errors explicitly.
14. Extend `CaptureController` and `DeepPacketEngine`.
15. Wire the CLI and UI to the shared engine API.
16. Update documentation with supported syntax and limitations.

## Compiler tests

Successful expressions:

```text
tcp
udp
icmp
arp
host 192.168.1.10
port 443
tcp and port 443
tcp or udp
not arp
(tcp or udp) and port 443
```

Invalid expressions:

```text
<empty>
http
host 999.1.1.1
port 70000
tcp and
(tcp or udp
tcp unexpected
```

Verify that:

- valid expressions compile successfully
- successful programs are non-empty
- invalid expressions return explicit errors
- no invalid program is exposed as a success
- operator precedence matches the grammar
- generated programs stay within the instruction limit

## Error and lifecycle rules

- Never silently ignore invalid filter text.
- Never start the capture thread if compilation or attachment fails.
- Preserve the previous capture state when replacing a running capture fails.
- Keep compile errors separate from socket attachment errors.
- Keep BPF program ownership alive while `setsockopt()` consumes it.
- Detach or release resources during failed startup and capture destruction.

## Relationship to the existing parser

The existing parser is useful as the semantic reference for:

- Ethernet type values
- IPv4 and IPv6 protocol fields
- TCP and UDP port fields
- ARP classification

The BPF compiler must remain separate from full user-space parsing because
kernel filtering happens before packets reach `PacketView`, validation, and the
SPSC queue.

## Future work

These are intentionally outside the first implementation:

- full Wireshark/libpcap syntax compatibility
- arbitrary payload searches
- complex IPv6 extension-header traversal
- user-space display filters
- filtering already-loaded PCAP summaries
- eBPF-specific features
