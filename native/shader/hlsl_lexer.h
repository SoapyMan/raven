#pragma once

#include <cstdint>
#include <functional>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace raven::shader {

enum class TokenKind { identifier, integer, floating, string, punct, end };

struct Token {
	TokenKind kind = TokenKind::end;
	std::string text;
	uint32_t line = 0;
	// The numeric value of an integer or floating literal; an integer literal with a u suffix is unsigned.
	double number = 0;
	bool is_unsigned = false;
};

struct Macro {
	std::string name;
	std::string value;
};

// Reads an #include: the text of the named file, or nothing when it cannot be found. `system` is true for <name>.
using IncludeReader = std::function<std::optional<std::string>(const std::string &name, bool system)>;

// The tokens of a source after preprocessing: #define (with parameters), #undef, #if/#ifdef/#ifndef/#elif/#else/#endif with defined(),
// #include, #pragma (ignored) and #error. Comments and line continuations are removed. Errors are reported as "name(line): message".
struct Preprocessed {
	std::vector<Token> tokens;
	std::string errors;
	bool failed = false;
};

Preprocessed preprocess(std::string_view source, std::string_view name, const std::vector<Macro> &macros, const IncludeReader &include);

}
