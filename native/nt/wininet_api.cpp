#include "child_process.h"
#include "kernel_context.h"
#include "text.h"

#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/x509v3.h>

#include <netdb.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>

#include <algorithm>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <functional>
#include <future>
#include <memory>
#include <optional>

namespace raven {

namespace {

// Error codes of the WinINet documentation.
constexpr uint32_t error_invalid_handle = 6, error_insufficient_buffer = 122, error_invalid_parameter = 87, internet_timeout = 12002,
	internet_invalid_option = 12009, internet_invalid_url = 12005, internet_unrecognized_scheme = 12006, internet_name_not_resolved = 12007,
	internet_incorrect_handle_type = 12018, internet_connection_aborted = 12030, internet_connection_reset = 12031,
	internet_cannot_connect = 12029, internet_date_invalid = 12037, internet_cn_invalid = 12038, internet_invalid_ca = 12045,
	internet_security_failure = 12157, http_header_not_found = 12150, http_invalid_server_response = 12152, http_redirect_failed = 12156;
// Request flags and security flags that change how a request is made.
constexpr uint32_t flag_secure = 0x00800000, flag_no_auto_redirect = 0x00200000, flag_ignore_cn = 0x00001000, flag_ignore_date = 0x00002000;
constexpr uint32_t security_ignore_unknown_ca = 0x100, security_ignore_cn = 0x1000, security_ignore_date = 0x2000, security_secure = 0x1;
constexpr uint32_t query_flag_number = 0x20000000, query_flag_request = 0x80000000, query_modifiers = 0xf0000000;

bool tracing()
{
	static const bool value = std::getenv("RAVEN_TRACE_WININET");
	return value;
}

std::string lower(std::string text)
{
	for (auto &character : text) character = char(std::tolower(static_cast<unsigned char>(character)));
	return text;
}

std::string trim(std::string_view text)
{
	const auto first = text.find_first_not_of(" \t"), last = text.find_last_not_of(" \t");
	return first == text.npos ? std::string() : std::string(text.substr(first, last - first + 1));
}

// One HTTP exchange on its own connection: it runs on a host thread while the guest thread that asked waits, so it never touches guest
// memory.
struct Exchange {
	int descriptor = -1;
	std::unique_ptr<SSL_CTX, decltype(&SSL_CTX_free)> tls_context{nullptr, SSL_CTX_free};
	std::unique_ptr<SSL, decltype(&SSL_free)> tls{nullptr, SSL_free};
	std::chrono::milliseconds connect_timeout{60000}, receive_timeout{60000};
	std::string input, body;
	std::string version, status_text;
	uint32_t status = 0;
	std::vector<std::pair<std::string, std::string>> headers;
	// How the body ends: after a length, after the last chunk, or when the server closes.
	enum class Framing { length, chunked, close } framing = Framing::close;
	uint64_t remaining = 0;
	bool finished = false;

	~Exchange()
	{
		tls.reset();
		if (descriptor >= 0) ::close(descriptor);
	}

	uint32_t open(const std::string &host, uint16_t port, bool secure, uint32_t security)
	{
		addrinfo hints{}, *found = nullptr;
		hints.ai_socktype = SOCK_STREAM;
		if (::getaddrinfo(host.c_str(), std::to_string(port).c_str(), &hints, &found) || !found)
			return internet_name_not_resolved;
		uint32_t error = internet_cannot_connect;
		for (auto *entry = found; entry && descriptor < 0; entry = entry->ai_next) {
			const int attempt = ::socket(entry->ai_family, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
			if (attempt < 0) continue;
			if (::connect(attempt, entry->ai_addr, entry->ai_addrlen) && errno != EINPROGRESS) { ::close(attempt); continue; }
			pollfd ready{attempt, POLLOUT, 0};
			int failure = 0;
			socklen_t size = sizeof failure;
			const int polled = ::poll(&ready, 1, int(connect_timeout.count()));
			if (polled <= 0 || ::getsockopt(attempt, SOL_SOCKET, SO_ERROR, &failure, &size) || failure) {
				if (!polled) error = internet_timeout;
				::close(attempt);
				continue;
			}
			descriptor = attempt;
		}
		::freeaddrinfo(found);
		if (descriptor < 0) return error;
		return secure ? handshake(host, security) : 0;
	}

	uint32_t handshake(const std::string &host, uint32_t security)
	{
		tls_context.reset(SSL_CTX_new(TLS_client_method()));
		if (!tls_context) return internet_security_failure;
		SSL_CTX_set_default_verify_paths(tls_context.get());
		tls.reset(SSL_new(tls_context.get()));
		if (!tls || !SSL_set_fd(tls.get(), descriptor)) return internet_security_failure;
		SSL_set_tlsext_host_name(tls.get(), host.c_str());
		if (!(security & security_ignore_cn)) SSL_set1_host(tls.get(), host.c_str());
		// The certificate is judged after the handshake, so each check the program waived can be left out.
		SSL_set_verify(tls.get(), SSL_VERIFY_NONE, nullptr);
		for (;;) {
			const int done = SSL_connect(tls.get());
			if (done == 1) break;
			const int reason = SSL_get_error(tls.get(), done);
			if ((reason != SSL_ERROR_WANT_READ && reason != SSL_ERROR_WANT_WRITE) ||
				!wait(reason == SSL_ERROR_WANT_READ ? POLLIN : POLLOUT, connect_timeout))
				return reason == SSL_ERROR_WANT_READ || reason == SSL_ERROR_WANT_WRITE ? internet_timeout : internet_security_failure;
		}
		const long verified = SSL_get_verify_result(tls.get());
		if (verified == X509_V_OK) return 0;
		if (verified == X509_V_ERR_HOSTNAME_MISMATCH) return security & security_ignore_cn ? 0 : internet_cn_invalid;
		if (verified == X509_V_ERR_CERT_HAS_EXPIRED || verified == X509_V_ERR_CERT_NOT_YET_VALID)
			return security & security_ignore_date ? 0 : internet_date_invalid;
		return security & security_ignore_unknown_ca ? 0 : internet_invalid_ca;
	}

	bool wait(short events, std::chrono::milliseconds timeout) const
	{
		pollfd ready{descriptor, events, 0};
		return ::poll(&ready, 1, int(timeout.count())) > 0;
	}

	uint32_t send(std::string_view data)
	{
		while (!data.empty()) {
			const long sent = tls ? SSL_write(tls.get(), data.data(), int(std::min<size_t>(data.size(), 1 << 20)))
				: ::send(descriptor, data.data(), data.size(), MSG_NOSIGNAL);
			if (sent > 0) { data.remove_prefix(size_t(sent)); continue; }
			const bool again = tls ? SSL_get_error(tls.get(), int(sent)) == SSL_ERROR_WANT_WRITE || SSL_get_error(tls.get(), int(sent)) == SSL_ERROR_WANT_READ
				: errno == EAGAIN;
			if (!again) return internet_connection_reset;
			if (!wait(POLLOUT | POLLIN, receive_timeout)) return internet_timeout;
		}
		return 0;
	}

	// More bytes from the connection into input; 0 and nothing added at the end of the stream.
	uint32_t receive()
	{
		char buffer[16384];
		for (;;) {
			const long got = tls ? SSL_read(tls.get(), buffer, sizeof buffer) : ::recv(descriptor, buffer, sizeof buffer, 0);
			if (got > 0) { input.append(buffer, size_t(got)); return 0; }
			if (tls) {
				const int reason = SSL_get_error(tls.get(), int(got));
				if (reason == SSL_ERROR_ZERO_RETURN || (reason == SSL_ERROR_SYSCALL && !got)) return 0;
				if (reason != SSL_ERROR_WANT_READ && reason != SSL_ERROR_WANT_WRITE) return internet_connection_aborted;
			} else if (!got) {
				return 0;
			} else if (errno != EAGAIN) {
				return internet_connection_reset;
			}
			if (!wait(POLLIN, receive_timeout)) return internet_timeout;
		}
	}

	uint32_t read_head()
	{
		size_t end;
		while ((end = input.find("\r\n\r\n")) == input.npos) {
			const size_t before = input.size();
			if (const auto error = receive()) return error;
			if (input.size() == before || input.size() > (1 << 20)) return http_invalid_server_response;
		}
		const std::string head = input.substr(0, end);
		input.erase(0, end + 4);
		size_t line_end = head.find("\r\n");
		const std::string status_line = head.substr(0, line_end);
		const auto first = status_line.find(' ');
		if (first == status_line.npos || !status_line.starts_with("HTTP/")) return http_invalid_server_response;
		version = status_line.substr(0, first);
		const auto second = status_line.find(' ', first + 1);
		status = uint32_t(std::strtoul(status_line.substr(first + 1, second - first - 1).c_str(), nullptr, 10));
		status_text = second == status_line.npos ? std::string() : status_line.substr(second + 1);
		while (line_end != head.npos) {
			const size_t start = line_end + 2;
			line_end = head.find("\r\n", start);
			const std::string line = head.substr(start, line_end == head.npos ? head.npos : line_end - start);
			const auto colon = line.find(':');
			if (colon != line.npos) headers.emplace_back(trim(line.substr(0, colon)), trim(std::string_view(line).substr(colon + 1)));
		}
		framing = Framing::close;
		for (const auto &[name, value] : headers) {
			if (lower(name) == "transfer-encoding" && lower(value).find("chunked") != std::string::npos) framing = Framing::chunked;
			else if (lower(name) == "content-length" && framing != Framing::chunked) {
				framing = Framing::length;
				remaining = std::strtoull(value.c_str(), nullptr, 10);
			}
		}
		if (status == 204 || status == 304 || (status >= 100 && status < 200)) { framing = Framing::length; remaining = 0; }
		finished = framing == Framing::length && !remaining;
		return 0;
	}

	// Decoded body bytes into body until there are at least wanted or the body ends.
	uint32_t fill(size_t wanted)
	{
		while (!finished && body.size() < wanted) {
			if (framing == Framing::length) {
				if (input.empty()) {
					if (const auto error = receive()) return error;
					if (input.empty()) return internet_connection_aborted;
				}
				const size_t taken = size_t(std::min<uint64_t>(remaining, input.size()));
				body.append(input, 0, taken);
				input.erase(0, taken);
				remaining -= taken;
				finished = !remaining;
			} else if (framing == Framing::close) {
				const size_t before = input.size();
				if (const auto error = receive()) return error;
				if (input.size() == before) finished = true;
				body += input;
				input.clear();
			} else if (remaining) {
				if (input.empty()) {
					if (const auto error = receive()) return error;
					if (input.empty()) return internet_connection_aborted;
				}
				const size_t taken = size_t(std::min<uint64_t>(remaining, input.size()));
				body.append(input, 0, taken);
				input.erase(0, taken);
				remaining -= taken;
			} else {
				// A chunk ends with CRLF and is followed by its size line; the last one, of size zero, by the trailer.
				size_t end;
				while ((end = input.find("\r\n", input.starts_with("\r\n") ? 2 : 0)) == input.npos) {
					const size_t before = input.size();
					if (const auto error = receive()) return error;
					if (input.size() == before) return internet_connection_aborted;
				}
				const size_t start = input.starts_with("\r\n") ? 2 : 0;
				remaining = std::strtoull(input.substr(start, end - start).c_str(), nullptr, 16);
				input.erase(0, end + 2);
				if (!remaining) {
					while (input.find("\r\n") == input.npos) {
						const size_t before = input.size();
						if (const auto error = receive()) return error;
						if (input.size() == before) break;
					}
					finished = true;
				}
			}
		}
		return 0;
	}
};

struct InternetHandle : KernelObject {
	// INTERNET_HANDLE_TYPE_INTERNET, INTERNET_HANDLE_TYPE_CONNECT_HTTP and INTERNET_HANDLE_TYPE_HTTP_REQUEST.
	uint32_t type = 1;
	std::shared_ptr<InternetHandle> parent;
	std::string agent, host, verb, path, user, password, request_headers, referrer;
	uint16_t port = 80;
	uint32_t flags = 0, security = 0;
	std::chrono::milliseconds connect_timeout{60000}, receive_timeout{60000};
	std::unique_ptr<Exchange> exchange;
	std::string url;
};

// Splits a URL into scheme, host, port and the path with its query; false when it is not an http or https URL.
bool crack(std::string_view url, bool &secure, std::string &host, uint16_t &port, std::string &path, uint32_t &error)
{
	const auto scheme_end = url.find("://");
	if (scheme_end == url.npos) { error = internet_unrecognized_scheme; return false; }
	const auto scheme = lower(std::string(url.substr(0, scheme_end)));
	if (scheme != "http" && scheme != "https") { error = internet_unrecognized_scheme; return false; }
	secure = scheme == "https";
	url.remove_prefix(scheme_end + 3);
	const auto authority_end = url.find_first_of("/?#");
	std::string authority(url.substr(0, authority_end));
	path = authority_end == url.npos ? "/" : std::string(url.substr(authority_end));
	if (path.starts_with('?')) path.insert(0, "/");
	if (const auto fragment = path.find('#'); fragment != path.npos) path.erase(fragment);
	if (const auto at = authority.rfind('@'); at != authority.npos) authority.erase(0, at + 1);
	port = secure ? 443 : 80;
	// A port follows the last colon, outside the brackets of an IPv6 address.
	const auto colon = authority.rfind(':'), bracket = authority.find(']');
	if (colon != authority.npos && (bracket == authority.npos ? authority.find(':') == colon : colon > bracket)) {
		const auto number = std::strtoul(authority.substr(colon + 1).c_str(), nullptr, 10);
		if (!number || number > 65535) { error = internet_invalid_url; return false; }
		port = uint16_t(number);
		authority.erase(colon);
	}
	if (authority.starts_with('[') && authority.ends_with(']')) authority = authority.substr(1, authority.size() - 2);
	host = authority;
	if (host.empty()) { error = internet_invalid_url; return false; }
	return true;
}

// Text a guest passed with an explicit length, or up to its terminator when the length is -1.
std::string counted(ApiCall &call, uint64_t address, uint32_t length, bool wide)
{
	if (!address) return {};
	if (length == UINT32_MAX || !length) return wide ? to_utf8(call.wide(address, 1 << 20)) : call.narrow(address, 1 << 20);
	if (!wide) {
		const auto bytes = call.read(address, length);
		return std::string(bytes.begin(), bytes.end());
	}
	const auto bytes = call.read(address, size_t(length) * 2);
	std::u16string text(length, u'\0');
	std::memcpy(text.data(), bytes.data(), bytes.size());
	return to_utf8(text);
}

}

// WinINet's synchronous HTTP client: sessions, connections and requests are handles, and a request is made, its response head read and
// its body streamed on a host thread while the guest thread that asked waits and the others run on.
void register_wininet_api(ApiRegistry &registry, KernelContext &context)
{
	auto &objects = context.objects;
	auto &threads = context.threads;
	const auto handle_of = [&objects](uint64_t handle, uint32_t type) -> std::shared_ptr<InternetHandle> {
		auto found = objects.object_as<InternetHandle>(handle);
		return found && (!type || found->type == type) ? found : nullptr;
	};
	const auto fail_handle = [&objects](ApiCall &call, uint64_t handle) {
		call.fail(objects.object_as<InternetHandle>(handle) ? internet_incorrect_handle_type : error_invalid_handle);
	};
	const auto add = [&objects](ApiCall &call, std::shared_ptr<InternetHandle> handle) {
		const auto made = objects.add_object(handle);
		if (made.status) { call.fail(8); return; }
		call.ret(made.value);
	};
	// Runs network work on a host thread; the calling guest thread waits for it and the other guest threads run meanwhile.
	const auto offload = [&threads](std::function<uint32_t()> work) {
		auto result = std::async(std::launch::async, std::move(work));
		HostWait waiting;
		threads.block([&] { return result.wait_for(std::chrono::seconds(0)) == std::future_status::ready; }, std::nullopt);
		return result.get();
	};

	const auto open = [add](ApiCall &call, bool wide) {
		auto session = std::make_shared<InternetHandle>();
		session->agent = call[0] ? (wide ? to_utf8(call.wide(call[0])) : call.narrow(call[0])) : std::string();
		session->flags = call.u32(4);
		add(call, session);
	};
	registry.add("InternetOpenW", 5, [open](ApiCall &call) { open(call, true); });
	registry.add("InternetOpenA", 5, [open](ApiCall &call) { open(call, false); });

	const auto connect = [handle_of, fail_handle, add](ApiCall &call, bool wide) {
		const auto session = handle_of(call[0], 1);
		if (!session) { fail_handle(call, call[0]); return; }
		const auto text = [&](size_t index) { return call[index] ? (wide ? to_utf8(call.wide(call[index])) : call.narrow(call[index])) : std::string(); };
		// INTERNET_SERVICE_HTTP is the only service this client speaks.
		if (call.u32(5) != 3 || !call[1]) { call.fail(error_invalid_parameter); return; }
		auto connection = std::make_shared<InternetHandle>();
		connection->type = 3;
		connection->parent = session;
		connection->host = text(1);
		connection->port = uint16_t(call.u32(2));
		connection->user = text(3);
		connection->password = text(4);
		connection->flags = call.u32(6);
		connection->connect_timeout = session->connect_timeout;
		connection->receive_timeout = session->receive_timeout;
		add(call, connection);
	};
	registry.add("InternetConnectW", 8, [connect](ApiCall &call) { connect(call, true); });
	registry.add("InternetConnectA", 8, [connect](ApiCall &call) { connect(call, false); });

	const auto open_request = [handle_of, fail_handle, add](ApiCall &call, bool wide) {
		const auto connection = handle_of(call[0], 3);
		if (!connection) { fail_handle(call, call[0]); return; }
		const auto text = [&](uint64_t address) { return address ? (wide ? to_utf8(call.wide(address)) : call.narrow(address)) : std::string(); };
		auto request = std::make_shared<InternetHandle>();
		request->type = 13;
		request->parent = connection;
		request->host = connection->host;
		request->verb = call[1] ? text(call[1]) : "GET";
		request->path = call[2] ? text(call[2]) : "/";
		if (!request->path.starts_with('/')) request->path.insert(0, "/");
		request->referrer = text(call[4]);
		request->flags = call.u32(6);
		request->security = request->flags & flag_secure ? security_secure : 0;
		if (request->flags & flag_ignore_cn) request->security |= security_ignore_cn;
		if (request->flags & flag_ignore_date) request->security |= security_ignore_date;
		request->port = connection->port ? connection->port : request->flags & flag_secure ? 443 : 80;
		request->connect_timeout = connection->connect_timeout;
		request->receive_timeout = connection->receive_timeout;
		// The accept types are a null-terminated array of strings.
		std::string accept;
		for (uint64_t at = call[5]; at && accept.size() < 4096; at += call.pointer_width()) {
			const auto entry = call.load_pointer(at);
			if (!entry) break;
			accept += (accept.empty() ? "" : ", ") + text(entry);
		}
		if (!accept.empty()) request->request_headers += "Accept: " + accept + "\r\n";
		add(call, request);
	};
	registry.add("HttpOpenRequestW", 8, [open_request](ApiCall &call) { open_request(call, true); });
	registry.add("HttpOpenRequestA", 8, [open_request](ApiCall &call) { open_request(call, false); });

	// Adds header lines, replacing a header of the same name when HTTP_ADDREQ_FLAG_REPLACE asks for it.
	const auto add_headers = [](InternetHandle &request, const std::string &text, uint32_t modifiers) {
		size_t start = 0;
		while (start < text.size()) {
			auto end = text.find("\r\n", start);
			if (end == text.npos) end = text.find('\n', start);
			const std::string line = trim(text.substr(start, end == text.npos ? text.npos : end - start));
			start = end == text.npos ? text.size() : text.find('\n', end) + 1;
			const auto colon = line.find(':');
			if (colon == line.npos) continue;
			const auto name = lower(trim(line.substr(0, colon)));
			std::string kept;
			bool present = false;
			for (size_t at = 0; at < request.request_headers.size();) {
				const auto next = request.request_headers.find("\r\n", at);
				const auto existing = request.request_headers.substr(at, next - at);
				const auto existing_colon = existing.find(':');
				const bool same = existing_colon != existing.npos && lower(trim(existing.substr(0, existing_colon))) == name;
				present |= same;
				if (!same || !(modifiers & 0x80000000U)) kept += existing + "\r\n";
				at = next + 2;
			}
			// HTTP_ADDREQ_FLAG_ADD_IF_NEW leaves a header that is already there.
			if (present && (modifiers & 0x10000000U)) continue;
			request.request_headers = kept;
			if (!trim(line.substr(colon + 1)).empty()) request.request_headers += line + "\r\n";
		}
	};
	const auto add_request_headers = [handle_of, fail_handle, add_headers](ApiCall &call, bool wide) {
		const auto request = handle_of(call[0], 13);
		if (!request) { fail_handle(call, call[0]); return; }
		add_headers(*request, counted(call, call[1], call.u32(2), wide), call.u32(3));
		call.ret(1);
	};
	registry.add("HttpAddRequestHeadersW", 4, [add_request_headers](ApiCall &call) { add_request_headers(call, true); });
	registry.add("HttpAddRequestHeadersA", 4, [add_request_headers](ApiCall &call) { add_request_headers(call, false); });

	// Sends the request and reads the response head, following redirects for a GET or HEAD unless the request said not to.
	const auto perform = [offload](InternetHandle &request, const std::string &extra, const std::string &body) -> uint32_t {
		const std::string agent = request.parent && request.parent->parent ? request.parent->parent->agent : std::string();
		for (int redirects = 0;; ++redirects) {
			const bool secure = request.flags & flag_secure;
			std::string head = request.verb + " " + request.path + " HTTP/1.1\r\nHost: " + request.host;
			if (request.port != (secure ? 443 : 80)) head += ":" + std::to_string(request.port);
			head += "\r\n";
			if (!agent.empty()) head += "User-Agent: " + agent + "\r\n";
			if (!request.referrer.empty()) head += "Referer: " + request.referrer + "\r\n";
			head += request.request_headers + extra;
			if (!extra.empty() && !extra.ends_with("\r\n")) head += "\r\n";
			if (!body.empty() || request.verb == "POST" || request.verb == "PUT") head += "Content-Length: " + std::to_string(body.size()) + "\r\n";
			head += "\r\n";
			auto exchange = std::make_unique<Exchange>();
			exchange->connect_timeout = request.connect_timeout;
			exchange->receive_timeout = request.receive_timeout;
			const std::string host = request.host;
			const uint16_t port = request.port;
			const uint32_t security = request.security;
			auto *raw = exchange.get();
			const uint32_t error = offload([raw, host, port, secure, security, head, body] {
				if (const auto failed = raw->open(host, port, secure, security)) return failed;
				if (const auto failed = raw->send(head + body)) return failed;
				return raw->read_head();
			});
			if (tracing())
				std::fprintf(stderr, "raven: wininet %s %s://%s:%u%s -> %u (error %u)\n", request.verb.c_str(), secure ? "https" : "http",
					host.c_str(), unsigned(port), request.path.c_str(), raw->status, error);
			if (error) return error;
			request.exchange = std::move(exchange);
			const auto status = request.exchange->status;
			const bool redirect = status == 301 || status == 302 || status == 303 || status == 307 || status == 308;
			if (!redirect || (request.flags & flag_no_auto_redirect) || (request.verb != "GET" && request.verb != "HEAD")) return 0;
			std::string location;
			for (const auto &[name, value] : request.exchange->headers)
				if (lower(name) == "location") location = value;
			if (location.empty() || redirects >= 10) return redirects >= 10 ? http_redirect_failed : 0;
			if (location.starts_with('/')) {
				request.path = location;
			} else {
				bool to_secure;
				uint32_t crack_error;
				if (!crack(location, to_secure, request.host, request.port, request.path, crack_error)) return http_redirect_failed;
				request.flags = to_secure ? request.flags | flag_secure : request.flags & ~flag_secure;
			}
		}
	};
	const auto send_request = [handle_of, fail_handle, perform](ApiCall &call, bool wide) {
		const auto request = handle_of(call[0], 13);
		if (!request) { fail_handle(call, call[0]); return; }
		const std::string extra = counted(call, call[1], call.u32(2), wide);
		std::string body;
		if (call[3] && call.u32(4)) {
			const auto bytes = call.read(call[3], call.u32(4));
			body.assign(bytes.begin(), bytes.end());
		}
		if (const auto error = perform(*request, extra, body)) { call.fail(error); return; }
		call.ret(1);
	};
	registry.add("HttpSendRequestW", 5, [send_request](ApiCall &call) { send_request(call, true); });
	registry.add("HttpSendRequestA", 5, [send_request](ApiCall &call) { send_request(call, false); });

	const auto open_url = [handle_of, fail_handle, add_headers, perform, &objects](ApiCall &call, bool wide) {
		const auto session = handle_of(call[0], 1);
		if (!session) { fail_handle(call, call[0]); return; }
		const std::string url = call[1] ? (wide ? to_utf8(call.wide(call[1])) : call.narrow(call[1])) : std::string();
		auto connection = std::make_shared<InternetHandle>();
		connection->type = 3;
		connection->parent = session;
		auto request = std::make_shared<InternetHandle>();
		request->type = 13;
		request->parent = connection;
		request->verb = "GET";
		request->url = url;
		request->flags = call.u32(4);
		bool secure;
		uint32_t error;
		if (!crack(url, secure, request->host, request->port, request->path, error)) { call.fail(error); return; }
		if (secure) request->flags |= flag_secure;
		request->security = (secure ? security_secure : 0) | (request->flags & flag_ignore_cn ? security_ignore_cn : 0) |
			(request->flags & flag_ignore_date ? security_ignore_date : 0);
		connection->host = request->host;
		connection->port = request->port;
		request->connect_timeout = session->connect_timeout;
		request->receive_timeout = session->receive_timeout;
		add_headers(*request, counted(call, call[2], call.u32(3), wide), 0);
		if (const auto failed = perform(*request, {}, {})) { call.fail(failed); return; }
		const auto made = objects.add_object(request);
		if (made.status) { call.fail(8); return; }
		call.ret(made.value);
	};
	registry.add("InternetOpenUrlW", 6, [open_url](ApiCall &call) { open_url(call, true); });
	registry.add("InternetOpenUrlA", 6, [open_url](ApiCall &call) { open_url(call, false); });

	registry.add("InternetReadFile", 4, [handle_of, fail_handle, offload](ApiCall &call) {
		const auto request = handle_of(call[0], 13);
		if (!request) { fail_handle(call, call[0]); return; }
		if (!call[3]) { call.fail(error_invalid_parameter); return; }
		const uint32_t wanted = call.u32(2);
		if (!request->exchange) { call.store<uint32_t>(call[3], 0); call.fail(12019); return; }
		auto *exchange = request->exchange.get();
		if (exchange->body.size() < wanted && !exchange->finished)
			if (const auto error = offload([exchange, wanted] { return exchange->fill(wanted); }); error && exchange->body.empty()) {
				call.store<uint32_t>(call[3], 0);
				call.fail(error);
				return;
			}
		const size_t taken = std::min<size_t>(wanted, exchange->body.size());
		if (taken) call.write(call[1], std::span<const uint8_t>(reinterpret_cast<const uint8_t *>(exchange->body.data()), taken));
		exchange->body.erase(0, taken);
		call.store<uint32_t>(call[3], uint32_t(taken));
		call.ret(1);
	});
	registry.add("InternetQueryDataAvailable", 4, [handle_of, fail_handle, offload](ApiCall &call) {
		const auto request = handle_of(call[0], 13);
		if (!request || !request->exchange) { fail_handle(call, call[0]); return; }
		auto *exchange = request->exchange.get();
		if (exchange->body.empty() && !exchange->finished)
			if (const auto error = offload([exchange] { return exchange->fill(1); }); error && exchange->body.empty()) { call.fail(error); return; }
		if (call[1]) call.store<uint32_t>(call[1], uint32_t(std::min<size_t>(exchange->body.size(), UINT32_MAX)));
		call.ret(1);
	});

	// HTTP_QUERY_* levels by header name; the status line parts and the raw head are answered apart.
	static const std::pair<uint32_t, const char *> names[] = {{1, "content-type"}, {2, "content-transfer-encoding"}, {5, "content-length"},
		{6, "content-language"}, {9, "date"}, {10, "expires"}, {11, "last-modified"}, {23, "connection"}, {29, "content-encoding"},
		{33, "location"}, {37, "server"}, {42, "accept-ranges"}, {43, "set-cookie"}, {44, "cookie"}, {47, "content-disposition"},
		{49, "cache-control"}, {54, "etag"}, {59, "host"}, {63, "transfer-encoding"}, {35, "user-agent"}, {39, "www-authenticate"},
		{45, "proxy-authenticate"}, {48, "content-range"}};
	const auto query_info = [handle_of, fail_handle](ApiCall &call, bool wide) {
		const auto request = handle_of(call[0], 13);
		if (!request) { fail_handle(call, call[0]); return; }
		if (!call[3]) { call.fail(error_invalid_parameter); return; }
		const uint32_t level = call.u32(1) & ~query_modifiers, modifiers = call.u32(1) & query_modifiers;
		if ((modifiers & query_flag_request) || !request->exchange) { call.fail(http_header_not_found); return; }
		const auto &exchange = *request->exchange;
		const uint32_t index = call[4] ? call.load<uint32_t>(call[4]) : 0;
		std::optional<std::string> answer;
		if (level == 19) answer = std::to_string(exchange.status);
		else if (level == 20) answer = exchange.status_text;
		else if (level == 18) answer = exchange.version;
		else if (level == 21 || level == 22) {
			// The raw head: lines separated by nulls and ended by two, or the lines as they came with CRLF.
			std::string text = exchange.version + " " + std::to_string(exchange.status) + (exchange.status_text.empty() ? "" : " " + exchange.status_text);
			const std::string separator = level == 22 ? "\r\n" : std::string(1, '\0');
			text += separator;
			for (const auto &[name, value] : exchange.headers) text += name + ": " + value + separator;
			text += separator;
			answer = text;
		} else {
			std::string wanted;
			if (level == 65535) wanted = lower(wide ? to_utf8(call.wide(call[2])) : call.narrow(call[2]));
			for (const auto &[id, name] : names)
				if (id == level) wanted = name;
			if (wanted.empty()) { call.fail(http_header_not_found); return; }
			uint32_t seen = 0;
			for (const auto &[name, value] : exchange.headers)
				if (lower(name) == wanted && seen++ == index) { answer = value; break; }
		}
		if (!answer) { call.fail(http_header_not_found); return; }
		const uint32_t capacity = call.load<uint32_t>(call[3]);
		if (modifiers & query_flag_number) {
			if (capacity < 4 || !call[2]) { call.store<uint32_t>(call[3], 4); call.fail(error_insufficient_buffer); return; }
			call.store<uint32_t>(call[2], uint32_t(std::strtoul(answer->c_str(), nullptr, 10)));
			call.store<uint32_t>(call[3], 4);
		} else if (wide) {
			const auto text = from_utf8(*answer);
			const size_t bytes = text.size() * 2;
			if (!call[2] || capacity < bytes + 2) { call.store<uint32_t>(call[3], uint32_t(bytes + 2)); call.fail(error_insufficient_buffer); return; }
			std::vector<uint8_t> out(bytes + 2, 0);
			std::memcpy(out.data(), text.data(), bytes);
			call.write(call[2], out);
			call.store<uint32_t>(call[3], uint32_t(bytes));
		} else {
			if (!call[2] || capacity < answer->size() + 1) { call.store<uint32_t>(call[3], uint32_t(answer->size() + 1)); call.fail(error_insufficient_buffer); return; }
			std::vector<uint8_t> out(answer->begin(), answer->end());
			out.push_back(0);
			call.write(call[2], out);
			call.store<uint32_t>(call[3], uint32_t(answer->size()));
		}
		if (call[4]) call.store<uint32_t>(call[4], index + 1);
		call.ret(1);
	};
	registry.add("HttpQueryInfoW", 5, [query_info](ApiCall &call) { query_info(call, true); });
	registry.add("HttpQueryInfoA", 5, [query_info](ApiCall &call) { query_info(call, false); });

	registry.add("InternetCloseHandle", 1, [&objects](ApiCall &call) {
		if (!objects.object_as<InternetHandle>(call[0])) { call.fail(error_invalid_handle); return; }
		objects.close(call[0]);
		call.ret(1);
	});
	// Timeouts and security flags are kept; other options are accepted and change nothing in this client.
	const auto set_option = [handle_of](ApiCall &call) {
		const uint32_t option = call.u32(1);
		const auto handle = call[0] ? handle_of(call[0], 0) : nullptr;
		if (call[0] && !handle) { call.fail(error_invalid_handle); return; }
		const uint32_t value = call[2] && call.u32(3) >= 4 ? call.load<uint32_t>(call[2]) : 0;
		if (handle) {
			if (option == 2) handle->connect_timeout = std::chrono::milliseconds(value);
			else if (option == 6) handle->receive_timeout = std::chrono::milliseconds(value);
			else if (option == 31) handle->security = value;
		}
		call.ret(1);
	};
	registry.add("InternetSetOptionW", 4, set_option);
	registry.add("InternetSetOptionA", 4, set_option);
	const auto query_option = [handle_of](ApiCall &call, bool wide) {
		const auto handle = call[0] ? handle_of(call[0], 0) : nullptr;
		const uint32_t option = call.u32(1);
		if (!call[3]) { call.fail(error_invalid_parameter); return; }
		const uint32_t capacity = call.load<uint32_t>(call[3]);
		std::optional<uint32_t> number;
		if (handle && option == 9) number = handle->type;
		else if (handle && option == 2) number = uint32_t(handle->connect_timeout.count());
		else if (handle && (option == 5 || option == 6)) number = uint32_t(handle->receive_timeout.count());
		else if (handle && option == 31) number = handle->security;
		if (number) {
			if (capacity < 4 || !call[2]) { call.store<uint32_t>(call[3], 4); call.fail(error_insufficient_buffer); return; }
			call.store<uint32_t>(call[2], *number);
			call.store<uint32_t>(call[3], 4);
			call.ret(1);
			return;
		}
		if (handle && option == 34 && handle->type == 13) {
			const bool secure = handle->flags & flag_secure;
			const std::string url = (secure ? "https://" : "http://") + handle->host +
				(handle->port != (secure ? 443 : 80) ? ":" + std::to_string(handle->port) : std::string()) + handle->path;
			const auto text = from_utf8(url);
			const size_t bytes = wide ? text.size() * 2 + 2 : url.size() + 1;
			if (capacity < bytes || !call[2]) { call.store<uint32_t>(call[3], uint32_t(bytes)); call.fail(error_insufficient_buffer); return; }
			if (wide) call.put_wide(call[2], text, text.size() + 1);
			else call.put_narrow(call[2], url, url.size() + 1);
			call.store<uint32_t>(call[3], uint32_t(bytes - (wide ? 2 : 1)));
			call.ret(1);
			return;
		}
		call.fail(handle || !call[0] ? internet_invalid_option : error_invalid_handle);
	};
	registry.add("InternetQueryOptionW", 4, [query_option](ApiCall &call) { query_option(call, true); });
	registry.add("InternetQueryOptionA", 4, [query_option](ApiCall &call) { query_option(call, false); });
	// No callback is ever made: every request completes before its call returns.
	registry.add("InternetSetStatusCallbackW", 2, [](ApiCall &call) { call.ret(0); });
	registry.add("InternetSetStatusCallbackA", 2, [](ApiCall &call) { call.ret(0); });
	registry.add("InternetSetStatusCallback", 2, [](ApiCall &call) { call.ret(0); });
	// INTERNET_CONNECTION_LAN: the host network is used directly.
	registry.add("InternetGetConnectedState", 2, [](ApiCall &call) {
		if (call[0]) call.store<uint32_t>(call[0], 2);
		call.ret(1);
	});
	const auto last_response = [](ApiCall &call) {
		if (call[0]) call.store<uint32_t>(call[0], 0);
		if (call[2]) call.store<uint32_t>(call[2], 0);
		call.ret(1);
	};
	registry.add("InternetGetLastResponseInfoW", 3, last_response);
	registry.add("InternetGetLastResponseInfoA", 3, last_response);
}

}
