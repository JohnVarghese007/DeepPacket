#include "dp/capture/bpf.hpp"

#include <arpa/inet.h>
#include <limits>
#include <linux/if_ether.h>
#include <memory>
#include <netinet/in.h>
#include <cctype>
#include <stdexcept>
#include <string>
#include <vector>
#include <utility>

namespace dp::capture {

namespace {

// === TOKEN MODEL === //
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

struct Token {
    TokenKind kind;
    std::string text;
    std::size_t position; 
};


// === AST MODEL === //
enum class FilterProtocol {
    TCP,
    UDP,
    ICMP,
    ARP
};

enum class PredicateKind {
    Protocol,
    Host,
    Port
};

struct Predicate {
    PredicateKind kind = PredicateKind::Protocol;
    FilterProtocol protocol = FilterProtocol::TCP; 
    std::string host_text;
    std::string port_text;
    std::uint32_t host_address = 0;
    std::uint16_t port = 0;
};

enum class ExpressionKind {
    Predicate,
    And,
    Or,
    Not
};

struct Expression {
    ExpressionKind kind = ExpressionKind::Predicate;
    Predicate predicate;
    std::unique_ptr<Expression> left;
    std::unique_ptr<Expression> right;
};


// === VALIDATION === //
enum class ValidationErrorKind {
    EmptyExpression,
    InvalidAddress,
    InvalidPort,
    PortOutOfRange
};


class ValidationError : public std::runtime_error {
public:
    ValidationError(
        ValidationErrorKind kind,
        const std::string& message
    )
        : std::runtime_error(message),
          kind(kind)
    {
    }

    ValidationErrorKind kind;
};


enum class GenerationErrorKind {
    UnsupportedExpression,
    ProgramTooLarge,
    EmptyProgram
};

class GenerationError : public std::runtime_error {
public:
    GenerationError(GenerationErrorKind kind, const std::string& message) : 
    std::runtime_error(message), kind(kind)   {}
    GenerationErrorKind kind;
};

std::uint32_t protocol_number(FilterProtocol protocol) {
    switch (protocol) {
    case FilterProtocol::TCP:
        return IPPROTO_TCP;

    case FilterProtocol::UDP:
        return IPPROTO_UDP;

    case FilterProtocol::ICMP:
        return IPPROTO_ICMP;

    case FilterProtocol::ARP:
        throw GenerationError(
            GenerationErrorKind::UnsupportedExpression,
            "ARP does not use an IPv4 protocol number"
        );
    }

    throw GenerationError(
        GenerationErrorKind::UnsupportedExpression,
        "unsupported protocol"
    );
}

std::vector<sock_filter> generate_protocol_program(
    FilterProtocol protocol
)
{
    std::vector<sock_filter> instructions;

    if (protocol == FilterProtocol::ARP) {
        instructions.push_back(
            BPF_STMT(
                BPF_LD | BPF_W | BPF_LEN,
                0
            )
        );

        instructions.push_back(
            BPF_JUMP(
                BPF_JMP | BPF_JGE | BPF_K,
                14,
                0,
                3
            )
        );

        instructions.push_back(
            BPF_STMT(
                BPF_LD | BPF_H | BPF_ABS,
                12
            )
        );

        instructions.push_back(
            BPF_JUMP(
                BPF_JMP | BPF_JEQ | BPF_K,
                ETH_P_ARP,
                0,
                1
            )
        );

        instructions.push_back(
            BPF_STMT(
                BPF_RET | BPF_K,
                0xffffffffU
            )
        );

        instructions.push_back(
            BPF_STMT(
                BPF_RET | BPF_K,
                0
            )
        );

        return instructions;
    }

    const std::uint32_t protocolValue =
        protocol_number(protocol);

    instructions.push_back(
        BPF_STMT(
            BPF_LD | BPF_W | BPF_LEN,
            0
        )
    );

    instructions.push_back(
        BPF_JUMP(
            BPF_JMP | BPF_JGE | BPF_K,
            24,
            0,
            5
        )
    );

    instructions.push_back(
        BPF_STMT(
            BPF_LD | BPF_H | BPF_ABS,
            12
        )
    );

    instructions.push_back(
        BPF_JUMP(
            BPF_JMP | BPF_JEQ | BPF_K,
            ETH_P_IP,
            0,
            3
        )
    );

    instructions.push_back(
        BPF_STMT(
            BPF_LD | BPF_B | BPF_ABS,
            23
        )
    );

    instructions.push_back(
        BPF_JUMP(
            BPF_JMP | BPF_JEQ | BPF_K,
            protocolValue,
            0,
            1
        )
    );

    instructions.push_back(
        BPF_STMT(
            BPF_RET | BPF_K,
            0xffffffffU
        )
    );

    instructions.push_back(
        BPF_STMT(
            BPF_RET | BPF_K,
            0
        )
    );

    return instructions;
}

std::vector<sock_filter> generate_host_program(uint32_t host_address) {
    std::vector<sock_filter> instructions;
    /* 
    Ethernet II + IPV4 header structure:
    Ethernet Type:  offset 12, 2 bytes
    IPV4 source address: offset 26, 4 bytes
    IPV4 dest address: offset 30, 4 bytes

    The minimum packet length to read the destination address is 34 bytes (14 bytes Ethernet + 20 bytes IP header). 

    */
    const std::uint32_t hostValue = ntohl(host_address);

    // Reject packets shorter than 34 bytes
    instructions.push_back(BPF_STMT(BPF_LD | BPF_W | BPF_LEN, 0));
    instructions.push_back(BPF_JUMP(BPF_JMP | BPF_JGE | BPF_K, 34, 0, 7));

    // Require that the Ethernet type is IPv4 (0x0800)
    instructions.push_back(BPF_STMT(BPF_LD | BPF_H | BPF_ABS, 12));
    instructions.push_back(BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, ETH_P_IP, 0, 5));

    // Compare the IPV4 source address (offset 26) with the host address
    instructions.push_back(BPF_STMT(BPF_LD | BPF_W | BPF_ABS, 26));
    instructions.push_back(BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, hostValue, 2, 0));

    // Compare the IPV4 destination address (offset 30) with the host address
    instructions.push_back(BPF_STMT(BPF_LD | BPF_W | BPF_ABS, 30));
    instructions.push_back(BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, hostValue, 0, 1));

    // Accept 
    instructions.push_back(BPF_STMT(BPF_RET | BPF_K, 0xffffffffU));

    // Reject
    instructions.push_back(BPF_STMT(BPF_RET | BPF_K, 0));

    return instructions;
}

std::vector<sock_filter> generate_port_program(uint16_t port) {
    std::vector<sock_filter> instructions;
    /* 
    Ethernet type:       offset 12, 2 bytes
    IPV4 protocol:       offset 23, 1 byte
    TCP/UDP source port: offset 34, 2 bytes
    TCP/UDP destination port: offset 36, 2 bytes

    The minimum packet length to read the destination port is 38 bytes   

    */

    // ntohs not needed
    const std::uint16_t portValue = port;

    // Reject packets shorter than 38 bytes
    instructions.push_back(BPF_STMT(BPF_LD | BPF_W | BPF_LEN, 0));
    instructions.push_back(BPF_JUMP(BPF_JMP | BPF_JGE | BPF_K, 38, 0, 12));

    // Require that the Ethernet type is IPv4 (0x0800)
    instructions.push_back(BPF_STMT(BPF_LD | BPF_H | BPF_ABS, 12));
    instructions.push_back(BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, ETH_P_IP, 0, 10));

    // Require a standard IPv4 header length of 20 bytes (IHL = 5)
    instructions.push_back(BPF_STMT(BPF_LD | BPF_B | BPF_ABS, 14));
    instructions.push_back(BPF_STMT(BPF_ALU | BPF_AND | BPF_K, 0x0F));
    instructions.push_back(BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 5, 0, 7));

    // Load the IPV4 protocol byte and check if it's TCP (6) or UDP (17)
    instructions.push_back(BPF_STMT(BPF_LD | BPF_B | BPF_ABS, 23));
    instructions.push_back(BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, IPPROTO_TCP, 1, 0));
    instructions.push_back(BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, IPPROTO_UDP, 0, 4));

    // Compare TCP/UDP source port
    instructions.push_back(BPF_STMT(BPF_LD | BPF_H | BPF_ABS, 34));
    instructions.push_back(BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, portValue, 3, 0));

    // Compare TCP/UDP destination port
    instructions.push_back(BPF_STMT(BPF_LD | BPF_H | BPF_ABS,36));
    instructions.push_back(BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, portValue, 1, 0));

    // Reject.
    instructions.push_back(BPF_STMT(BPF_RET | BPF_K, 0));

    // Accept.
    instructions.push_back(BPF_STMT(BPF_RET | BPF_K, 0xffffffffU)); 
    return instructions;
}


struct GeneratedExpression {
    std::vector<sock_filter> instructions;
    std::vector<std::size_t> true_sites;   // currently matched indices
    std::vector<std::size_t> false_sites;  // currently unmatched indices
};

void patch_unconditional_jump(GeneratedExpression& expr, std::size_t instruction_index, std::size_t target_index) {
    if(target_index <= instruction_index) {
        throw GenerationError(
            GenerationErrorKind::UnsupportedExpression,
            "BPF jump target must be forward in the instruction stream"
        );
    }
    const std::size_t offset = target_index - instruction_index - 1;

    if(offset > std::numeric_limits<std::uint32_t>::max()) {
        throw GenerationError(
            GenerationErrorKind::ProgramTooLarge,
            "BPF jump offset is too large"
        );
    }

    // Forward JA jump
    expr.instructions.at(instruction_index) = BPF_STMT(
            BPF_JMP | BPF_JA | BPF_K,
            static_cast<std::uint32_t>(offset)
        );
}

GeneratedExpression make_leaf_expression(std::vector<sock_filter> instructions) {
    // Initialize with instructions
    GeneratedExpression expr;
    expr.instructions = std::move(instructions);

    for(std::size_t i = 0; i < expr.instructions.size(); ++i) {
        const sock_filter& instruction = expr.instructions[i];
        if((instruction.code == (BPF_RET | BPF_K)) && (instruction.k == 0xffffffffU)) {
            expr.instructions[i] = BPF_STMT(BPF_JMP | BPF_JA | BPF_K, 0); // placeholder for jump offset
            expr.true_sites.push_back(i);
        }
        else if((instruction.code == (BPF_RET | BPF_K)) && (instruction.k == 0)) {
            expr.instructions[i] = BPF_STMT(BPF_JMP | BPF_JA | BPF_K, 0); // placeholder for jump offset
            expr.false_sites.push_back(i);
        }
    }

    if(expr.true_sites.empty() || expr.false_sites.empty()) {
        throw GenerationError(
            GenerationErrorKind::UnsupportedExpression,
            "generated predicate has no complete true/false paths"
        );
    }
    return expr;

}



GeneratedExpression combine_and(
    GeneratedExpression left,
    GeneratedExpression right
)
{
    const std::size_t rightStart =
        left.instructions.size();

    for (std::size_t site : left.true_sites) {
        patch_unconditional_jump(
            left,
            site,
            rightStart
        );
    }

    GeneratedExpression result;
    result.instructions =
        std::move(left.instructions);

    result.false_sites =
        std::move(left.false_sites);

    const std::size_t rightOffset =
        result.instructions.size();

    result.instructions.insert(
        result.instructions.end(),
        right.instructions.begin(),
        right.instructions.end()
    );

    for (std::size_t site : right.true_sites) {
        result.true_sites.push_back(
            site + rightOffset
        );
    }

    for (std::size_t site : right.false_sites) {
        result.false_sites.push_back(
            site + rightOffset
        );
    }

    return result;
}


GeneratedExpression combine_or(
    GeneratedExpression left,
    GeneratedExpression right
)
{
    const std::size_t rightStart =
        left.instructions.size();

    for (std::size_t site : left.false_sites) {
        patch_unconditional_jump(
            left,
            site,
            rightStart
        );
    }

    GeneratedExpression result;
    result.instructions =
        std::move(left.instructions);

    result.true_sites =
        std::move(left.true_sites);

    const std::size_t rightOffset =
        result.instructions.size();

    result.instructions.insert(
        result.instructions.end(),
        right.instructions.begin(),
        right.instructions.end()
    );

    for (std::size_t site : right.true_sites) {
        result.true_sites.push_back(
            site + rightOffset
        );
    }

    for (std::size_t site : right.false_sites) {
        result.false_sites.push_back(
            site + rightOffset
        );
    }

    return result;
}


GeneratedExpression combine_not(
    GeneratedExpression expression
)
{
    std::swap(
        expression.true_sites,
        expression.false_sites
    );

    return expression;
}


GeneratedExpression generate_expression(
    const Expression& expression
)
{
    switch (expression.kind) {
    case ExpressionKind::Predicate:
        switch (expression.predicate.kind) {
        case PredicateKind::Protocol:
            return make_leaf_expression(
                generate_protocol_program(
                    expression.predicate.protocol
                )
            );

        case PredicateKind::Host:
            return make_leaf_expression(
                generate_host_program(
                    expression.predicate.host_address
                )
            );

        case PredicateKind::Port:
            return make_leaf_expression(
                generate_port_program(
                    expression.predicate.port
                )
            );
        }

        throw GenerationError(
            GenerationErrorKind::UnsupportedExpression,
            "unsupported predicate"
        );

    case ExpressionKind::And:
        if (!expression.left || !expression.right) {
            throw GenerationError(
                GenerationErrorKind::UnsupportedExpression,
                "and expression is missing an operand"
            );
        }

        return combine_and(
            generate_expression(*expression.left),
            generate_expression(*expression.right)
        );

    case ExpressionKind::Or:
        if (!expression.left || !expression.right) {
            throw GenerationError(
                GenerationErrorKind::UnsupportedExpression,
                "or expression is missing an operand"
            );
        }

        return combine_or(
            generate_expression(*expression.left),
            generate_expression(*expression.right)
        );

    case ExpressionKind::Not:
        if (!expression.left) {
            throw GenerationError(
                GenerationErrorKind::UnsupportedExpression,
                "not expression is missing an operand"
            );
        }

        return combine_not(
            generate_expression(*expression.left)
        );
    }

    throw GenerationError(
        GenerationErrorKind::UnsupportedExpression,
        "unsupported expression kind"
    );
}


std::vector<sock_filter> finalize_expression(
    GeneratedExpression expression
)
{
    const std::size_t acceptIndex =
        expression.instructions.size();

    expression.instructions.push_back(
        BPF_STMT(
            BPF_RET | BPF_K,
            0xffffffffU
        )
    );

    const std::size_t rejectIndex =
        expression.instructions.size();

    expression.instructions.push_back(
        BPF_STMT(
            BPF_RET | BPF_K,
            0
        )
    );

    for (std::size_t site : expression.true_sites) {
        patch_unconditional_jump(
            expression,
            site,
            acceptIndex
        );
    }

    for (std::size_t site : expression.false_sites) {
        patch_unconditional_jump(
            expression,
            site,
            rejectIndex
        );
    }

    return std::move(expression.instructions);
}

void enforce_program_limit(
    const std::vector<sock_filter>& instructions
)
{
    if (instructions.empty()) {
        throw GenerationError(
            GenerationErrorKind::EmptyProgram,
            "generated BPF program is empty"
        );
    }

    if (instructions.size() > BPF_MAXINSNS) {
        throw GenerationError(
            GenerationErrorKind::ProgramTooLarge,
            "generated BPF program exceeds BPF_MAXINSNS"
        );
    }
}


// Lexer functions
void skip_whitespace(const std::string& expr, std::size_t& pos) {
    while(pos < expr.size() && std::isspace(static_cast<unsigned char>(expr[pos]))) {
        ++pos;
    }
}

Token scan_identifier(const std::string& expr, std::size_t& pos) {
    std::size_t start = pos;
    while(pos < expr.size() && (std::isalnum(static_cast<unsigned char>(expr[pos])) || expr[pos] == '_')) {
        ++pos;
    }
    const std::string text = expr.substr(start, pos - start);

    TokenKind kind = TokenKind::Identifier;

    if(text == "and") {
        kind = TokenKind::And;
    } else if(text == "or") {
        kind = TokenKind::Or;
    } else if(text == "not") {
        kind = TokenKind::Not;
    }

    return Token{kind, text, start};
}
Token scan_number_or_ipv4(const std::string& expr, std::size_t& pos) {
    std::size_t start = pos;
    bool is_address = false;

    while(pos < expr.size()) {
        const char curr = expr[pos];
        if(std::isdigit(static_cast<unsigned char>(curr))) {
            ++pos;
        } else if(curr == '.') {
            is_address = true;
            ++pos;
        } else {
            break;
        }
    }

    const std::string text = expr.substr(start, pos - start);
    TokenKind kind = is_address ? TokenKind::IPv4Address : TokenKind::Number;

    return Token{kind, text, start};
}


bool is_whitespace_only(const std::string& expression)
{
    for (char character : expression) {
        if (!std::isspace(
                static_cast<unsigned char>(character)
            )) {
            return false;
        }
    }

    return true;
}


std::vector<Token> tokenize(const std::string& expr) {
    std::vector<Token> tokens;
    std::size_t pos = 0;

    // read through the expression string and produce tokens
    while(pos < expr.size()) {
        skip_whitespace(expr, pos);

        if(pos >= expr.size()) {
            break;
        }

        const char current = expr[pos]; // 

        if(std::isalpha(static_cast<unsigned char>(current))) {
            tokens.push_back(scan_identifier(expr, pos));
        }
        else if (std::isdigit(static_cast<unsigned char>(current))) {
            tokens.push_back(scan_number_or_ipv4(expr, pos));
        }
        else if(current == '(') {
            tokens.push_back(Token{TokenKind::LeftParen, "(", pos});
            ++pos;
        }
        else if(current == ')') {
            tokens.push_back(Token{TokenKind::RightParen, ")", pos});
            ++pos;
        }
        else {
            throw std::runtime_error("invalid character in filter expression at position " + std::to_string(pos));
        }
    }

    // Append an end token if we reach here
    tokens.push_back(Token{TokenKind::End, "", pos});

    return tokens;
}


// AST construction helpers
std::unique_ptr<Expression> make_predicate_expression(Predicate predicate) {
    auto expr = std::make_unique<Expression>();
    expr->kind = ExpressionKind::Predicate;
    expr->predicate = std::move(predicate);
    return expr;
}
std::unique_ptr<Expression> make_binary_expression(ExpressionKind kind, std::unique_ptr<Expression> left, std::unique_ptr<Expression> right) {
    auto expr = std::make_unique<Expression>();
    expr->kind = kind;
    expr->left = std::move(left);
    expr->right = std::move(right);
    return expr;
}
std::unique_ptr<Expression> make_unary_expression(ExpressionKind kind, std::unique_ptr<Expression> operand) {
    auto expr = std::make_unique<Expression>();
    expr->kind = kind;
    expr->left = std::move(operand);
    return expr;
}

// === PARSER === //
class Parser {
public:
    explicit Parser(const std::vector<Token>& tokens) : tokens(tokens) {};

    std::unique_ptr<Expression> parse();

private:
    const std::vector<Token>& tokens;
    std::size_t current = 0;

    const Token& peek() const;
    const Token& previous() const;
    bool is_at_end() const;

    const Token& advance();
    bool check(TokenKind kind) const;
    bool match(TokenKind kind); 

    const Token& expect(TokenKind kind, const std::string& msg);

    std::unique_ptr<Expression> parse_expression();
    std::unique_ptr<Expression> parse_or_expression();
    std::unique_ptr<Expression> parse_and_expression();
    std::unique_ptr<Expression> parse_unary_expression();
    std::unique_ptr<Expression> parse_primary();
    std::unique_ptr<Expression> parse_predicate();

    Predicate parse_protocol_predicate(const Token& token);
    Predicate parse_host_predicate(const Token&);
    Predicate parse_port_predicate(const Token&);
};

const Token& Parser::peek() const {
    return tokens.at(current); // diff between this an tokens[current] is that at() does bounds checking and throws if out of range
}

const Token& Parser::previous() const {
    return tokens.at(current - 1);
}

bool Parser::is_at_end() const {
    return peek().kind == TokenKind::End;
}

const Token& Parser::advance() {
    if (!is_at_end()) {
        ++current;
    }
    return previous(); // return the token that was just consumed
}

bool Parser::check(TokenKind kind) const {
    return peek().kind == kind;
}

bool Parser::match(TokenKind kind) {
    if (!check(kind)) {
        return false;
    }
    advance();
    return true;
}

const Token& Parser::expect(TokenKind kind, const std::string& msg) {
    if(!check(kind)) {
        throw std::runtime_error(msg + " at position " + std::to_string(peek().position));
    }
    return advance();
}

std::unique_ptr<Expression> Parser::parse() {
    auto expr = parse_expression();
    expect(TokenKind::End, "expected end of expression");
    return expr;
}

std::unique_ptr<Expression> Parser::parse_expression() {
    return parse_or_expression();
}

std::unique_ptr<Expression> Parser::parse_or_expression() {
    // Giving and a higher precedence than or
    auto expr = parse_and_expression();

    while (match(TokenKind::Or)) {
        // If we find an 'or', parse the right operand
        auto right = parse_and_expression();
        expr = make_binary_expression(ExpressionKind::Or, std::move(expr), std::move(right));
    }
    return expr;
}

std::unique_ptr<Expression> Parser::parse_and_expression() {
    // Giving not a higher precedence than and
    auto expr = parse_unary_expression();

    while (match(TokenKind::And)) {
        // If we find an 'and', parse the right operand
        auto right = parse_unary_expression();
        expr = make_binary_expression(ExpressionKind::And, std::move(expr), std::move(right));
    }
    return expr;
}

std::unique_ptr<Expression> Parser::parse_unary_expression() {
    if(match(TokenKind::Not)) {
        auto operand = parse_unary_expression();
        return make_unary_expression(ExpressionKind::Not, std::move(operand));
    }
    return parse_primary();
}

std::unique_ptr<Expression> Parser::parse_primary() {
    if(match(TokenKind::LeftParen)) {
        auto expr = parse_expression();
        expect(TokenKind::RightParen, "expected ')' after grouped expression");
        return expr;
    }
    return parse_predicate();
}

std::unique_ptr<Expression> Parser::parse_predicate() {
    const Token& token = expect(TokenKind::Identifier, "expected protocol or predicate");

    if (token.text == "tcp" || token.text == "udp" || token.text == "icmp" || token.text == "arp" ) {
        return make_predicate_expression(parse_protocol_predicate(token));
    }

    if (token.text == "host") {
        return make_predicate_expression(parse_host_predicate(token));
    }

    if (token.text == "port") {
        return make_predicate_expression(parse_port_predicate(token));
    }

    throw std::runtime_error("unknown predicate '" + token.text + "' at position " + std::to_string(token.position));

}

Predicate Parser::parse_protocol_predicate(const Token& token) {
    Predicate predicate;
    predicate.kind = PredicateKind::Protocol;

    if (token.text == "tcp") {
        predicate.protocol = FilterProtocol::TCP;
    } else if (token.text == "udp") {
        predicate.protocol = FilterProtocol::UDP;
    } else if (token.text == "icmp") {
        predicate.protocol = FilterProtocol::ICMP;
    } else if (token.text == "arp") {
        predicate.protocol = FilterProtocol::ARP;
    } else {
        throw std::runtime_error("unknown protocol '" + token.text + "' at position " + std::to_string(token.position));
    }

    return predicate;
}

Predicate Parser::parse_host_predicate(const Token&) {
    const Token& address = expect(TokenKind::IPv4Address, "expected IPv4 address after 'host'");

    Predicate predicate;
    predicate.kind = PredicateKind::Host;
    predicate.host_text = address.text;
    return predicate;
}

Predicate Parser::parse_port_predicate(const Token&) {

    if(check(TokenKind::End) || check(TokenKind::And) || check(TokenKind::Or) || check(TokenKind::RightParen)) {
        throw std::runtime_error("expected port number after 'port' at position " + std::to_string(peek().position));
    }
    const Token& port_token = advance();

    if(port_token.kind != TokenKind::Number && port_token.kind != TokenKind::Identifier) {
        throw std::runtime_error("expected port number after 'port' at position " + std::to_string(port_token.position));
    }
    Predicate predicate;
    predicate.kind = PredicateKind::Port;
    predicate.port_text = port_token.text;
    return predicate;
}


// === SEMANTIC VALIDATION === //
std::uint32_t validate_ipv4(const std::string& text) {
    in_addr address{};

    if (inet_pton(AF_INET, text.c_str(), &address) != 1) {
        throw ValidationError(ValidationErrorKind::InvalidAddress, "invalid IPv4 address '" + text + "'");
    }

    return address.s_addr;
}

std::uint16_t validate_port(const std::string& text) {
    std::size_t parsedLength = 0;
    unsigned long value = 0;

    try {
        // try to parse the string as an unsigned long
        value = std::stoul(text, &parsedLength);
    }
    catch (const std::invalid_argument&) {
        throw ValidationError(ValidationErrorKind::InvalidPort, "invalid port '" + text + "'");
    }
    catch (const std::out_of_range&) {
        throw ValidationError(ValidationErrorKind::PortOutOfRange, "port '" + text + "' is out of range");
    }

    if (parsedLength != text.size()) {
        throw ValidationError(ValidationErrorKind::InvalidPort, "invalid port '" + text + "'");
    }

    if (value > std::numeric_limits<std::uint16_t>::max()) {
        throw ValidationError(ValidationErrorKind::PortOutOfRange, "port '" + text + "' is outside the range 0..65535");
    }

    return static_cast<std::uint16_t>(value);
}


void validate_expression(Expression& expr) {

    // switch on the kind of expression
    switch (expr.kind) {
        case ExpressionKind::Predicate:
            // validate predicate based on kind
            switch (expr.predicate.kind) {
                case PredicateKind::Protocol:
                    return; // No validation needed since protocol is already validated during parsing
                case PredicateKind::Host:
                    expr.predicate.host_address = validate_ipv4(expr.predicate.host_text);
                    return;
                case PredicateKind::Port:
                    expr.predicate.port = validate_port(expr.predicate.port_text);
                    return;
            }

            // Add exception for unsupported predicate kind
            throw std::runtime_error("unsupported predicate kind");

            case ExpressionKind::And:
            case ExpressionKind::Or:
                if (!expr.left || !expr.right) {
                    throw std::runtime_error("binary expression missing operand");
                }
                validate_expression(*expr.left);
                validate_expression(*expr.right);
                return;

            case ExpressionKind::Not:
                if (!expr.left) {
                    throw std::runtime_error("unary expression missing operand");
                }
                validate_expression(*expr.left);
                return;
    }
}


// Public error classifications
BPFCompileError classify_parser_error(const std::string& msg) {
    if ( msg.find("unknown predicate") != std::string::npos ||
         msg.find("unknown protocol") != std::string::npos
    ) {
        return BPFCompileError::UNKNOWN_KEYWORD;
    }

    if ( msg.find("expected protocol or predicate") != std::string::npos ||
         msg.find("expected IPv4 address") != std::string::npos ||
         msg.find("expected port number") != std::string::npos ||
         msg.find("missing operand") != std::string::npos
    ) {
        return BPFCompileError::MISSING_OPERAND;
    }

    if ( msg.find("expected end") != std::string::npos ||
         msg.find("expected ')'") != std::string::npos ||
         msg.find("invalid character") != std::string::npos
    ) {
        return BPFCompileError::UNEXPECTED_TOKEN;
    }

    return BPFCompileError::INTERNAL_ERROR;
}

} // namespace

BPFCompileResult BPFProgram::compile(const std::string& expression) {
    BPFCompileResult result;

    if (expression.empty() || is_whitespace_only(expression)) {
        result.error = BPFCompileError::EMPTY_EXPRESSION;
        result.message = "filter expression cannot be empty";
        return result;
    }

    try {
        const std::vector<Token> tokens = tokenize(expression);
        Parser parser(tokens);
        std::unique_ptr<Expression> ast = parser.parse();

        if (!ast) {
            result.error = BPFCompileError::INTERNAL_ERROR;
            result.message = "parser returned an empty expression";
            return result;
        }

        validate_expression(*ast);

        GeneratedExpression generated = generate_expression(*ast);
        std::vector<sock_filter> instructions = finalize_expression(std::move(generated));

        enforce_program_limit(instructions);

        result.program.instructions = std::move(instructions);

        result.success = true;
        result.error = BPFCompileError::NONE;
        result.message = "filter expression compiled successfully";
        return result;
    }
    catch (const ValidationError& error) {
        switch (error.kind) {
        case ValidationErrorKind::InvalidAddress:
            result.error = BPFCompileError::INVALID_ADDRESS;
            break;

        case ValidationErrorKind::InvalidPort:
            result.error = BPFCompileError::INVALID_PORT;
            break;

        case ValidationErrorKind::PortOutOfRange:
            result.error = BPFCompileError::PORT_OUT_OF_RANGE;
            break;

        case ValidationErrorKind::EmptyExpression:
            result.error = BPFCompileError::EMPTY_EXPRESSION;
            break;
        }

        result.message = error.what();
        return result;
    }
    catch  (const GenerationError& error) {
        switch (error.kind) {
            case GenerationErrorKind::UnsupportedExpression:
                result.error = BPFCompileError::UNSUPPORTED_EXPRESSION;
                break;
            case GenerationErrorKind::ProgramTooLarge:
                result.error = BPFCompileError::PROGRAM_TOO_LARGE;
                break;
            case GenerationErrorKind::EmptyProgram:
                result.error = BPFCompileError::INTERNAL_ERROR;
                break;
        }
        result.message = error.what();
        return result;
    }
    catch (const std::runtime_error& error) {
        result.error = classify_parser_error(error.what());
        result.message = error.what();
        return result;
    }
    catch (const std::exception& error) {
        result.error = BPFCompileError::INTERNAL_ERROR;
        result.message = error.what();
        return result;
    }
}


} // namespace dp::capture