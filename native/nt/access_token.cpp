#include "access_token.h"
#include "elevation.h"

#include <algorithm>
#include <cerrno>
#include <cstring>
#include <fcntl.h>
#include <stdexcept>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

namespace raven {

std::optional<uint32_t> token_access(uint32_t requested)
{
	if (requested & ~0xf20f01ffU)
		return std::nullopt;
	uint32_t access = requested & 0xf01ff;
	if (requested & (0x10000000U | 0x02000000U)) access |= 0xf01ff;
	if (requested & 0x80000000U) access |= 0x20008;
	if (requested & 0x40000000U) access |= 0x200e0;
	if (requested & 0x20000000U) access |= 0x20000;
	return access;
}

struct AccessToken::Shared {
	uint32_t integrity, type, acl_size, impersonation_level;
	uint32_t privilege_count;
	Privilege privileges[64];
	uint8_t acl[65535];
};

namespace {

class TokenLock {
public:
	TokenLock(int descriptor, bool write) : descriptor(descriptor)
	{
		struct flock lock{};
		lock.l_type = write ? F_WRLCK : F_RDLCK;
		lock.l_whence = SEEK_SET;
		int result;
		do result = ::fcntl(descriptor, F_SETLKW, &lock); while (result < 0 && errno == EINTR);
		if (result < 0)
			throw std::runtime_error("cannot lock access token storage");
	}
	~TokenLock()
	{
		struct flock lock{};
		lock.l_type = F_UNLCK;
		lock.l_whence = SEEK_SET;
		::fcntl(descriptor, F_SETLK, &lock);
	}

private:
	int descriptor;
};

}

void AccessToken::map()
{
	struct stat information{};
	if (descriptor < 0 || ::fstat(descriptor, &information) || information.st_size != sizeof(Shared))
		throw std::runtime_error("invalid access token storage");
	const auto mapped = ::mmap(nullptr, sizeof(Shared), PROT_READ | PROT_WRITE, MAP_SHARED, descriptor, 0);
	if (mapped == MAP_FAILED)
		throw std::runtime_error("cannot map access token storage");
	shared = static_cast<Shared *>(mapped);
}

AccessToken::AccessToken()
{
	descriptor = ::memfd_create("raven-token", MFD_CLOEXEC | MFD_ALLOW_SEALING);
	try {
		if (descriptor < 0 || ::ftruncate(descriptor, sizeof(Shared)) ||
			::fcntl(descriptor, F_ADD_SEALS, F_SEAL_SHRINK | F_SEAL_GROW | F_SEAL_SEAL))
			throw std::runtime_error("cannot create access token storage");
		map();
		// Medium integrity, or high in a process that runs elevated, as an administrator's full token is.
		shared->integrity = process_elevated() ? 12288 : 8192;
		shared->type = 1;
		shared->impersonation_level = 2;
		shared->privilege_count = 1;
		shared->privileges[0] = {23, 3};
	} catch (...) {
		if (descriptor >= 0) ::close(descriptor);
		throw;
	}
}

AccessToken::AccessToken(int descriptor) : descriptor(descriptor)
{
	try { map(); }
	catch (...) { if (descriptor >= 0) ::close(descriptor); throw; }
}

AccessToken::AccessToken(const AccessToken &other) : AccessToken()
{
	const auto value = other.data();
	shared->integrity = value.integrity;
	shared->type = value.type;
	shared->impersonation_level = value.impersonation_level;
	shared->acl_size = uint32_t(value.default_dacl.size());
	shared->privilege_count = uint32_t(value.privileges.size());
	std::copy(value.privileges.begin(), value.privileges.end(), shared->privileges);
	if (!value.default_dacl.empty())
		std::memcpy(shared->acl, value.default_dacl.data(), value.default_dacl.size());
}

AccessToken::~AccessToken()
{
	if (shared) ::munmap(shared, sizeof(Shared));
	if (descriptor >= 0) ::close(descriptor);
}

bool AccessToken::describe(InheritedHandle &record) const
{
	record.kind = "token";
	record.descriptor = descriptor;
	return true;
}

AccessToken::Data AccessToken::data() const
{
	const TokenLock lock(descriptor, false);
	if (shared->acl_size > sizeof(shared->acl) || shared->privilege_count > std::size(shared->privileges))
		throw std::runtime_error("invalid access token storage size");
	return {{shared->acl, shared->acl + shared->acl_size}, shared->integrity, shared->type, shared->impersonation_level,
		{shared->privileges, shared->privileges + shared->privilege_count}};
}

void AccessToken::set_default_dacl(std::span<const uint8_t> acl)
{
	if (acl.size() > sizeof(shared->acl))
		throw std::runtime_error("access token ACL exceeds storage");
	const TokenLock lock(descriptor, true);
	if (!acl.empty())
		std::memcpy(shared->acl, acl.data(), acl.size());
	shared->acl_size = uint32_t(acl.size());
}

void AccessToken::set_integrity(uint32_t value)
{
	const TokenLock lock(descriptor, true);
	shared->integrity = value;
}

void AccessToken::set_type(uint32_t value)
{
	const TokenLock lock(descriptor, true);
	shared->type = value;
}

void AccessToken::set_impersonation_level(uint32_t value)
{
	const TokenLock lock(descriptor, true);
	shared->impersonation_level = value;
}

void AccessToken::restrict_privileges(bool maximum, std::span<const uint64_t> removed)
{
	const TokenLock lock(descriptor, true);
	if (shared->privilege_count > std::size(shared->privileges))
		throw std::runtime_error("invalid access token privilege count");
	uint32_t count = 0;
	for (uint32_t index = 0; index < shared->privilege_count; ++index) {
		const auto privilege = shared->privileges[index];
		if (maximum ? privilege.luid != 23 : std::find(removed.begin(), removed.end(), privilege.luid) != removed.end())
			continue;
		shared->privileges[count++] = privilege;
	}
	shared->privilege_count = count;
}

uint32_t AccessToken::adjust_privileges(bool disable, std::span<const Privilege> changes,
	const std::function<uint32_t(std::span<const Privilege>)> &prepare)
{
	const TokenLock lock(descriptor, true);
	if (shared->privilege_count > std::size(shared->privileges))
		throw std::runtime_error("invalid access token privilege count");
	const std::vector<Privilege> original(shared->privileges, shared->privileges + shared->privilege_count);
	auto next = original;
	bool assigned = true;
	if (disable) {
		for (auto &privilege : next) privilege.attributes &= ~2U;
	} else {
		for (const auto &change : changes) {
			const auto found = std::find_if(next.begin(), next.end(), [&](const auto &privilege) { return privilege.luid == change.luid; });
			if (found == next.end()) {
				assigned = false;
				continue;
			}
			if (change.attributes & 4)
				next.erase(found);
			else
				found->attributes = (found->attributes & ~2U) | (change.attributes & 2);
		}
	}
	std::vector<Privilege> previous;
	for (const auto &privilege : original) {
		const auto found = std::find_if(next.begin(), next.end(), [&](const auto &entry) { return entry.luid == privilege.luid; });
		if (found != next.end() && found->attributes != privilege.attributes)
			previous.push_back(privilege);
	}
	if (const auto error = prepare(previous))
		return error;
	std::copy(next.begin(), next.end(), shared->privileges);
	shared->privilege_count = uint32_t(next.size());
	return assigned ? 0 : 1300;
}

}
