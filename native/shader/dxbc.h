#pragma once

#include <array>
#include <cstdint>
#include <span>
#include <string_view>
#include <vector>

namespace raven::shader {

// One part of a compiled shader: a four character tag (RDEF, ISGN, OSGN, SHDR, SHEX, STAT...) and its bytes.
struct Chunk {
	std::array<char, 4> tag;
	std::vector<uint8_t> data;
};

// The DXBC container the Direct3D runtimes read: header, checksum, chunk offsets and chunks, in the order given.
std::vector<uint8_t> container(std::span<const Chunk> chunks);

// The container checksum: MD5 over everything after the checksum field, with the length folded into the final padding the way
// Direct3D runtimes verify it.
std::array<uint32_t, 4> container_checksum(std::span<const uint8_t> blob);

// The chunks of a container, found by their offsets; empty when the bytes are not a well-formed container.
std::vector<Chunk> read_container(std::span<const uint8_t> blob);

// Little-endian building of chunk bodies.
class Writer {
public:
	void u32(uint32_t value);
	void f32(float value);
	void bytes(std::span<const uint8_t> data);
	// A zero-terminated string, padded to a four byte boundary when asked.
	void text(std::string_view value, bool align = false);
	void align(size_t boundary);
	size_t size() const { return data.size(); }
	void patch(size_t offset, uint32_t value);
	std::vector<uint8_t> take() { return std::move(data); }

private:
	std::vector<uint8_t> data;
};

}
