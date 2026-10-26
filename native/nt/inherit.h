#pragma once

#include <cstdint>
#include <span>
#include <string>
#include <vector>

namespace raven {

// A handle that a new process receives from its creator: what kind of object it is, the host descriptor behind it (in the creator, then
// the number it has in the new process) and the details needed to rebuild the object there.
struct InheritedHandle {
	uint64_t handle = 0;
	std::string kind;
	int descriptor = -1;
	uint32_t access = 0, flags = 0, bits = 0;
	// The rights the creator's handle carries (a section handle can be read-only, for instance).
	uint32_t handle_access = 0;
	uint64_t size = 0;
	std::u16string text;
	std::string path;
	// The standard handles (bit 0 input, 1 output, 2 error) the creator named this handle for, which the child takes it as.
	uint32_t standard = 0;
};

std::vector<uint8_t> serialize_inherited(const std::vector<InheritedHandle> &handles);
std::vector<InheritedHandle> parse_inherited(std::span<const uint8_t> bytes);

}
