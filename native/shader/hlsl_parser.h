#pragma once

#include "hlsl_ast.h"
#include "hlsl_lexer.h"

#include <string>
#include <vector>

namespace raven::shader {

struct Parsed {
	Program program;
	std::string errors;
	bool failed = false;
};

// The declarations of a preprocessed source. Errors are reported as "name(line): error: message", and parsing stops at the first one.
Parsed parse(const std::vector<Token> &tokens, std::string_view name);

}
