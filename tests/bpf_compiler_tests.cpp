#include "dp/capture/bpf.hpp"

#include <iostream>
#include <string>

namespace {

int failures = 0;

void check(bool condition, const std::string& description)
{
    if (condition) {
        std::cout << "PASS: " << description << '\n';
    } else {
        std::cerr << "FAIL: " << description << '\n';
        ++failures;
    }
}

void check_success(const std::string& expression)
{
    const dp::capture::BPFCompileResult result =
        dp::capture::BPFProgram::compile(expression);

    check(
        result.success,
        expression + " should compile successfully"
    );

    check(
        result.success && !result.program.empty(),
        expression + " should produce a non-empty program"
    );

    check(
        result.success &&
        result.error == dp::capture::BPFCompileError::NONE,
        expression + " should return BPFCompileError::NONE"
    );

    check(
        result.success && result.message.empty() == false,
        expression + " should provide a success message"
    );
}

void check_error(
    const std::string& expression,
    dp::capture::BPFCompileError expected_error
)
{
    const dp::capture::BPFCompileResult result =
        dp::capture::BPFProgram::compile(expression);

    check(
        !result.success,
        expression + " should fail"
    );

    check(
        !result.success && result.error == expected_error,
        expression + " should return the expected error category"
    );

    check(
        !result.success && !result.message.empty(),
        expression + " should provide an error message"
    );

    check(
        !result.success && result.program.empty(),
        expression + " should not produce a program"
    );
}

} // namespace

int main()
{
    std::cout << "==== BPF COMPILER TESTS ====\n";

    // Simple predicates.
    check_success("tcp");
    check_success("udp");
    check_success("icmp");
    check_success("arp");
    check_success("host 192.168.1.10");
    check_success("port 443");

    // Boolean operators.
    check_success("tcp and port 443");
    check_success("tcp or udp");
    check_success("not arp");

    // Parentheses and precedence.
    check_success("(tcp or udp) and port 443");
    check_success("tcp and (udp or icmp)");
    check_success("not (tcp or udp)");
    check_success("(host 192.168.1.10 and tcp)");
    check_success("not (host 192.168.1.10 or port 443)");

    // Whitespace around a valid expression.
    check_success("  tcp and port 443  ");

    // Empty input.
    check_error(
        "",
        dp::capture::BPFCompileError::EMPTY_EXPRESSION
    );

    check_error(
        "   ",
        dp::capture::BPFCompileError::EMPTY_EXPRESSION
    );

    // Unknown keywords and protocols.
    check_error(
        "banana",
        dp::capture::BPFCompileError::UNKNOWN_KEYWORD
    );

    check_error(
        "sctp",
        dp::capture::BPFCompileError::UNKNOWN_KEYWORD
    );

    // Invalid addresses.
    check_error(
        "host 999.999.999.999",
        dp::capture::BPFCompileError::INVALID_ADDRESS
    );

    check_error(
        "host 192.168.1",
        dp::capture::BPFCompileError::INVALID_ADDRESS
    );

    // Invalid and out-of-range ports.
    check_error(
        "port nope",
        dp::capture::BPFCompileError::INVALID_PORT
    );

    check_error(
        "port 65536",
        dp::capture::BPFCompileError::PORT_OUT_OF_RANGE
    );

    // Missing operands and malformed expressions.
    check_error(
        "tcp and",
        dp::capture::BPFCompileError::MISSING_OPERAND
    );

    check_error(
        "and tcp",
        dp::capture::BPFCompileError::MISSING_OPERAND
    );

    check_error(
        "host",
        dp::capture::BPFCompileError::MISSING_OPERAND
    );

    check_error(
        "port",
        dp::capture::BPFCompileError::MISSING_OPERAND
    );

    check_error(
        "(tcp or udp",
        dp::capture::BPFCompileError::UNEXPECTED_TOKEN
    );

    check_error(
        "tcp udp",
        dp::capture::BPFCompileError::UNEXPECTED_TOKEN
    );

    std::cout << "\n";

    if (failures == 0) {
        std::cout << "All BPF compiler tests passed.\n";
        return 0;
    }

    std::cerr << failures << " BPF compiler test checks failed.\n";
    return 1;
}