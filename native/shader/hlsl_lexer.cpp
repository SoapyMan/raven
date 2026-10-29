#include "hlsl_lexer.h"

#include <cctype>
#include <cstdlib>
#include <map>
#include <set>

namespace raven::shader {

namespace {

struct Definition {
	bool function = false;
	std::vector<std::string> parameters;
	std::vector<Token> body;
};

bool identifier_start(char c) { return std::isalpha(static_cast<unsigned char>(c)) || c == '_'; }
bool identifier_part(char c) { return std::isalnum(static_cast<unsigned char>(c)) || c == '_'; }

// The punctuators of the language, longest first so that a scan takes the longest match.
constexpr std::string_view punctuators[] = {"<<=", ">>=", "...", "##", "++", "--", "<<", ">>", "<=", ">=", "==", "!=", "&&", "||", "+=", "-=",
	"*=", "/=", "%=", "&=", "|=", "^=", "::", "->"};

// The tokens of one logical line.
std::vector<Token> tokenize(std::string_view text, uint32_t line, std::string &errors, std::string_view name)
{
	std::vector<Token> tokens;
	size_t at = 0;
	while (at < text.size()) {
		const char c = text[at];
		if (std::isspace(static_cast<unsigned char>(c))) {
			++at;
			continue;
		}
		Token token;
		token.line = line;
		const size_t start = at;
		if (identifier_start(c)) {
			while (at < text.size() && identifier_part(text[at]))
				++at;
			token.kind = TokenKind::identifier;
		} else if (std::isdigit(static_cast<unsigned char>(c)) || (c == '.' && at + 1 < text.size() && std::isdigit(static_cast<unsigned char>(text[at + 1])))) {
			bool floating = false;
			if (c == '0' && at + 1 < text.size() && (text[at + 1] == 'x' || text[at + 1] == 'X')) {
				at += 2;
				while (at < text.size() && std::isxdigit(static_cast<unsigned char>(text[at])))
					++at;
				token.number = double(std::strtoull(std::string(text.substr(start + 2, at - start - 2)).c_str(), nullptr, 16));
			} else {
				while (at < text.size() && (std::isdigit(static_cast<unsigned char>(text[at])) || text[at] == '.')) {
					floating |= text[at] == '.';
					++at;
				}
				if (at < text.size() && (text[at] == 'e' || text[at] == 'E')) {
					size_t exponent = at + 1;
					if (exponent < text.size() && (text[exponent] == '+' || text[exponent] == '-'))
						++exponent;
					if (exponent < text.size() && std::isdigit(static_cast<unsigned char>(text[exponent]))) {
						floating = true;
						at = exponent;
						while (at < text.size() && std::isdigit(static_cast<unsigned char>(text[at])))
							++at;
					}
				}
				const std::string digits(text.substr(start, at - start));
				// A leading zero in an integer means octal, as in C.
				if (!floating && digits.size() > 1 && digits[0] == '0')
					token.number = double(std::strtoull(digits.c_str(), nullptr, 8));
				else
					token.number = std::strtod(digits.c_str(), nullptr);
			}
			while (at < text.size() && std::isalpha(static_cast<unsigned char>(text[at]))) {
				const char suffix = char(std::tolower(static_cast<unsigned char>(text[at])));
				if (suffix == 'f' || suffix == 'h')
					floating = true;
				else if (suffix == 'u')
					token.is_unsigned = true;
				++at;
			}
			token.kind = floating ? TokenKind::floating : TokenKind::integer;
		} else if (c == '"') {
			++at;
			while (at < text.size() && text[at] != '"') {
				if (text[at] == '\\' && at + 1 < text.size())
					++at;
				++at;
			}
			if (at >= text.size())
				errors += std::string(name) + "(" + std::to_string(line) + "): error: unterminated string\n";
			else
				++at;
			token.kind = TokenKind::string;
		} else {
			token.kind = TokenKind::punct;
			size_t length = 1;
			for (const auto candidate : punctuators)
				if (text.substr(at, candidate.size()) == candidate) {
					length = candidate.size();
					break;
				}
			at += length;
		}
		token.text = std::string(text.substr(start, at - start));
		tokens.push_back(std::move(token));
	}
	return tokens;
}

// The source as logical lines: comments become spaces, a backslash before a newline joins lines, and each line keeps the number of the
// physical line it starts on.
std::vector<std::pair<uint32_t, std::string>> logical_lines(std::string_view source)
{
	std::vector<std::pair<uint32_t, std::string>> lines;
	std::string current;
	uint32_t line = 1, start = 1;
	bool in_block = false, in_string = false;
	for (size_t at = 0; at < source.size(); ++at) {
		const char c = source[at];
		if (in_block) {
			if (c == '*' && at + 1 < source.size() && source[at + 1] == '/') {
				in_block = false;
				++at;
				current += ' ';
			} else if (c == '\n')
				++line;
			continue;
		}
		if (!in_string && c == '/' && at + 1 < source.size() && source[at + 1] == '/') {
			while (at + 1 < source.size() && source[at + 1] != '\n')
				++at;
			continue;
		}
		if (!in_string && c == '/' && at + 1 < source.size() && source[at + 1] == '*') {
			in_block = true;
			++at;
			continue;
		}
		if (c == '\\' && (at + 1 < source.size() && (source[at + 1] == '\n' || (source[at + 1] == '\r' && at + 2 < source.size() && source[at + 2] == '\n')))) {
			at += source[at + 1] == '\r' ? 2 : 1;
			++line;
			continue;
		}
		if (c == '"')
			in_string = !in_string;
		if (c == '\n') {
			lines.emplace_back(start, std::move(current));
			current.clear();
			in_string = false;
			start = ++line;
			continue;
		}
		if (c != '\r')
			current += c;
	}
	lines.emplace_back(start, std::move(current));
	return lines;
}

class Preprocessor {
public:
	Preprocessor(const IncludeReader &include, Preprocessed &out) : include(include), out(out) {}

	std::map<std::string, Definition> definitions;

	void run(std::string_view source, std::string_view name, int depth)
	{
		if (depth > 32) {
			fail(name, 0, "includes nest too deeply");
			return;
		}
		struct Branch {
			bool active, taken, parent;
		};
		std::vector<Branch> branches;
		const auto active = [&] { return branches.empty() || branches.back().active; };
		for (auto &[line, text] : logical_lines(source)) {
			size_t first = text.find_first_not_of(" \t");
			if (first != std::string::npos && text[first] == '#') {
				auto tokens = tokenize(std::string_view(text).substr(first + 1), line, out.errors, name);
				const std::string directive = tokens.empty() ? "" : tokens[0].text;
				std::vector<Token> rest(tokens.begin() + (tokens.empty() ? 0 : 1), tokens.end());
				if (directive == "if" || directive == "ifdef" || directive == "ifndef") {
					const bool parent = active();
					bool value = false;
					if (parent) {
						if (directive == "if")
							value = evaluate(rest, name, line);
						else
							value = !rest.empty() && definitions.contains(rest[0].text) == (directive == "ifdef");
					}
					branches.push_back({parent && value, value, parent});
				} else if (directive == "elif") {
					if (branches.empty()) {
						fail(name, line, "#elif without #if");
						continue;
					}
					auto &branch = branches.back();
					const bool value = branch.parent && !branch.taken && evaluate(rest, name, line);
					branch.active = value;
					branch.taken |= value;
				} else if (directive == "else") {
					if (branches.empty()) {
						fail(name, line, "#else without #if");
						continue;
					}
					auto &branch = branches.back();
					branch.active = branch.parent && !branch.taken;
					branch.taken = true;
				} else if (directive == "endif") {
					if (branches.empty())
						fail(name, line, "#endif without #if");
					else
						branches.pop_back();
				} else if (!active())
					continue;
				else if (directive == "define")
					define(rest, text, name, line);
				else if (directive == "undef") {
					if (!rest.empty())
						definitions.erase(rest[0].text);
				} else if (directive == "include") {
					if (rest.empty() || (rest[0].kind != TokenKind::string && rest[0].text != "<")) {
						fail(name, line, "#include expects a file name");
						continue;
					}
					std::string file;
					bool system = false;
					if (rest[0].kind == TokenKind::string)
						file = rest[0].text.substr(1, rest[0].text.size() - 2);
					else {
						system = true;
						const auto open = text.find('<'), close = text.find('>', open);
						file = close == std::string::npos ? "" : text.substr(open + 1, close - open - 1);
					}
					const auto content = include ? include(file, system) : std::nullopt;
					if (!content)
						fail(name, line, "cannot open include file '" + file + "'");
					else
						run(*content, file, depth + 1);
				} else if (directive == "error")
					fail(name, line, "#error" + text.substr(text.find("error") + 5));
				else if (directive == "pragma" || directive == "line" || directive.empty()) {
				} else
					fail(name, line, "unknown directive #" + directive);
				continue;
			}
			if (!active())
				continue;
			auto tokens = tokenize(text, line, out.errors, name);
			pending.insert(pending.end(), tokens.begin(), tokens.end());
			// A call of a function-like macro may span lines; tokens wait until its parentheses close.
			if (!waiting_for_arguments())
				flush();
		}
		flush();
		if (!branches.empty())
			fail(name, 0, "missing #endif");
	}

private:
	const IncludeReader &include;
	Preprocessed &out;
	std::vector<Token> pending;

	void fail(std::string_view name, uint32_t line, const std::string &message)
	{
		out.errors += std::string(name) + "(" + std::to_string(line) + "): error: " + message + "\n";
		out.failed = true;
	}

	bool waiting_for_arguments() const
	{
		for (size_t at = 0; at < pending.size(); ++at) {
			const auto found = definitions.find(pending[at].text);
			if (pending[at].kind != TokenKind::identifier || found == definitions.end() || !found->second.function)
				continue;
			if (at + 1 == pending.size())
				return true;
			if (pending[at + 1].text != "(")
				continue;
			int depth = 0;
			size_t close = at + 1;
			for (; close < pending.size(); ++close) {
				depth += pending[close].text == "(" ? 1 : pending[close].text == ")" ? -1 : 0;
				if (!depth)
					break;
			}
			if (close == pending.size())
				return true;
		}
		return false;
	}

	void flush()
	{
		std::set<std::string> hidden;
		auto expanded = expand(pending, hidden);
		out.tokens.insert(out.tokens.end(), expanded.begin(), expanded.end());
		pending.clear();
	}

	void define(const std::vector<Token> &tokens, const std::string &text, std::string_view name, uint32_t line)
	{
		if (tokens.empty() || tokens[0].kind != TokenKind::identifier) {
			fail(name, line, "#define expects a name");
			return;
		}
		Definition definition;
		size_t at = 1;
		// A parameter list only when the parenthesis touches the name.
		const auto name_at = text.find(tokens[0].text, text.find("define") + 6);
		if (tokens.size() > 1 && tokens[1].text == "(" && name_at != std::string::npos && name_at + tokens[0].text.size() < text.size() &&
			text[name_at + tokens[0].text.size()] == '(') {
			definition.function = true;
			at = 2;
			while (at < tokens.size() && tokens[at].text != ")") {
				if (tokens[at].kind == TokenKind::identifier)
					definition.parameters.push_back(tokens[at].text);
				++at;
			}
			++at;
		}
		if (at < tokens.size())
			definition.body.assign(tokens.begin() + at, tokens.end());
		definitions[tokens[0].text] = std::move(definition);
	}

	std::vector<Token> expand(const std::vector<Token> &input, std::set<std::string> &hidden)
	{
		std::vector<Token> result;
		for (size_t at = 0; at < input.size(); ++at) {
			const auto &token = input[at];
			const auto found = token.kind == TokenKind::identifier && !hidden.contains(token.text) ? definitions.find(token.text) : definitions.end();
			if (found == definitions.end()) {
				result.push_back(token);
				continue;
			}
			const auto &definition = found->second;
			std::vector<Token> body;
			if (!definition.function)
				body = definition.body;
			else {
				if (at + 1 >= input.size() || input[at + 1].text != "(") {
					result.push_back(token);
					continue;
				}
				std::vector<std::vector<Token>> arguments(1);
				int depth = 0;
				size_t close = at + 1;
				for (++close; close < input.size(); ++close) {
					const auto &item = input[close];
					if (item.text == "(")
						++depth;
					else if (item.text == ")") {
						if (!depth)
							break;
						--depth;
					} else if (item.text == "," && !depth) {
						arguments.emplace_back();
						continue;
					}
					arguments.back().push_back(item);
				}
				if (arguments.size() == 1 && arguments[0].empty() && definition.parameters.empty())
					arguments.clear();
				at = close;
				for (size_t index = 0; index < definition.body.size(); ++index) {
					const auto &part = definition.body[index];
					size_t parameter = definition.parameters.size();
					const auto parameter_of = [&](const Token &item) {
						for (size_t p = 0; p < definition.parameters.size(); ++p)
							if (item.kind == TokenKind::identifier && item.text == definition.parameters[p])
								return p;
						return definition.parameters.size();
					};
					if (part.text == "#" && index + 1 < definition.body.size() &&
						(parameter = parameter_of(definition.body[index + 1])) < arguments.size()) {
						Token text_token{TokenKind::string, "\"", part.line};
						for (size_t a = 0; a < arguments[parameter].size(); ++a)
							text_token.text += (a ? " " : "") + arguments[parameter][a].text;
						text_token.text += "\"";
						body.push_back(text_token);
						++index;
						continue;
					}
					if ((parameter = parameter_of(part)) < arguments.size()) {
						// An argument next to ## is pasted as written; elsewhere it is expanded first.
						const bool pasted = (index > 0 && definition.body[index - 1].text == "##") ||
							(index + 1 < definition.body.size() && definition.body[index + 1].text == "##");
						std::set<std::string> inner = hidden;
						const auto value = pasted ? arguments[parameter] : expand(arguments[parameter], inner);
						body.insert(body.end(), value.begin(), value.end());
					} else
						body.push_back(part);
				}
			}
			// Token pasting joins the neighbours of each ##.
			for (size_t index = 0; index < body.size();) {
				if (body[index].text == "##" && index > 0 && index + 1 < body.size()) {
					std::string errors;
					auto joined = tokenize(body[index - 1].text + body[index + 1].text, token.line, errors, "");
					body.erase(body.begin() + long(index - 1), body.begin() + long(index + 2));
					body.insert(body.begin() + long(index - 1), joined.begin(), joined.end());
				} else
					++index;
			}
			for (auto &part : body)
				part.line = token.line;
			hidden.insert(token.text);
			auto again = expand(body, hidden);
			hidden.erase(token.text);
			result.insert(result.end(), again.begin(), again.end());
		}
		return result;
	}

	// An #if expression: defined() first, then macros, then the remaining names count as zero.
	bool evaluate(const std::vector<Token> &tokens, std::string_view name, uint32_t line)
	{
		std::vector<Token> prepared;
		for (size_t at = 0; at < tokens.size(); ++at) {
			if (tokens[at].text == "defined") {
				size_t next = at + 1;
				const bool parenthesis = next < tokens.size() && tokens[next].text == "(";
				if (parenthesis)
					++next;
				Token value{TokenKind::integer, "0", line};
				if (next < tokens.size()) {
					value.number = definitions.contains(tokens[next].text) ? 1 : 0;
					value.text = value.number ? "1" : "0";
				}
				at = next + (parenthesis ? 1 : 0);
				prepared.push_back(value);
			} else
				prepared.push_back(tokens[at]);
		}
		std::set<std::string> hidden;
		auto expanded = expand(prepared, hidden);
		size_t at = 0;
		bool bad = false;
		const long long value = expression(expanded, at, 0, bad);
		if (bad || at != expanded.size()) {
			fail(name, line, "invalid #if expression");
			return false;
		}
		return value != 0;
	}

	static int precedence(const std::string &op)
	{
		static const std::map<std::string, int> table{{"||", 1}, {"&&", 2}, {"|", 3}, {"^", 4}, {"&", 5}, {"==", 6}, {"!=", 6}, {"<", 7}, {">", 7},
			{"<=", 7}, {">=", 7}, {"<<", 8}, {">>", 8}, {"+", 9}, {"-", 9}, {"*", 10}, {"/", 10}, {"%", 10}};
		const auto found = table.find(op);
		return found == table.end() ? -1 : found->second;
	}

	long long primary(const std::vector<Token> &tokens, size_t &at, bool &bad)
	{
		if (at >= tokens.size()) {
			bad = true;
			return 0;
		}
		const auto &token = tokens[at++];
		if (token.text == "(") {
			const long long value = expression(tokens, at, 0, bad);
			if (at >= tokens.size() || tokens[at].text != ")")
				bad = true;
			else
				++at;
			return value;
		}
		if (token.text == "!")
			return !primary(tokens, at, bad);
		if (token.text == "-")
			return -primary(tokens, at, bad);
		if (token.text == "+")
			return primary(tokens, at, bad);
		if (token.text == "~")
			return ~primary(tokens, at, bad);
		if (token.kind == TokenKind::integer || token.kind == TokenKind::floating)
			return (long long)token.number;
		if (token.kind == TokenKind::identifier)
			return 0;
		bad = true;
		return 0;
	}

	long long expression(const std::vector<Token> &tokens, size_t &at, int minimum, bool &bad)
	{
		long long left = primary(tokens, at, bad);
		while (at < tokens.size() && !bad) {
			if (tokens[at].text == "?" && minimum == 0) {
				++at;
				const long long yes = expression(tokens, at, 0, bad);
				if (at >= tokens.size() || tokens[at].text != ":") {
					bad = true;
					return 0;
				}
				++at;
				const long long no = expression(tokens, at, 0, bad);
				left = left ? yes : no;
				continue;
			}
			const int level = precedence(tokens[at].text);
			if (level < 0 || level < minimum)
				break;
			const std::string op = tokens[at++].text;
			const long long right = expression(tokens, at, level + 1, bad);
			if (op == "||") left = left || right;
			else if (op == "&&") left = left && right;
			else if (op == "|") left |= right;
			else if (op == "^") left ^= right;
			else if (op == "&") left &= right;
			else if (op == "==") left = left == right;
			else if (op == "!=") left = left != right;
			else if (op == "<") left = left < right;
			else if (op == ">") left = left > right;
			else if (op == "<=") left = left <= right;
			else if (op == ">=") left = left >= right;
			else if (op == "<<") left <<= right;
			else if (op == ">>") left >>= right;
			else if (op == "+") left += right;
			else if (op == "-") left -= right;
			else if (op == "*") left *= right;
			else if (op == "/" || op == "%") {
				if (!right) {
					bad = true;
					return 0;
				}
				left = op == "/" ? left / right : left % right;
			}
		}
		return left;
	}
};

}

Preprocessed preprocess(std::string_view source, std::string_view name, const std::vector<Macro> &macros, const IncludeReader &include)
{
	Preprocessed out;
	Preprocessor preprocessor(include, out);
	for (const auto &macro : macros) {
		std::string errors;
		Definition definition;
		definition.body = tokenize(macro.value.empty() ? "1" : macro.value, 0, errors, name);
		preprocessor.definitions[macro.name] = std::move(definition);
	}
	preprocessor.run(source, name, 0);
	Token end;
	end.kind = TokenKind::end;
	end.line = out.tokens.empty() ? 1 : out.tokens.back().line;
	out.tokens.push_back(end);
	return out;
}

}
