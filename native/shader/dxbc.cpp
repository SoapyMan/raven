#include "dxbc.h"

#include <bit>
#include <cmath>
#include <cstring>

namespace raven::shader {

namespace {

uint32_t load32(const uint8_t *at)
{
	return uint32_t(at[0]) | uint32_t(at[1]) << 8 | uint32_t(at[2]) << 16 | uint32_t(at[3]) << 24;
}

void md5_block(std::array<uint32_t, 4> &state, const uint8_t *block)
{
	static constexpr uint8_t shifts[64] = {7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20,
		5, 9, 14, 20, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21};
	static const auto constants = [] {
		std::array<uint32_t, 64> table{};
		for (int index = 0; index < 64; ++index)
			table[index] = uint32_t(uint64_t(std::fabs(std::sin(double(index + 1))) * 4294967296.0));
		return table;
	}();
	uint32_t words[16];
	for (int index = 0; index < 16; ++index)
		words[index] = load32(block + index * 4);
	uint32_t a = state[0], b = state[1], c = state[2], d = state[3];
	for (int index = 0; index < 64; ++index) {
		uint32_t mixed;
		int word;
		if (index < 16) {
			mixed = (b & c) | (~b & d);
			word = index;
		} else if (index < 32) {
			mixed = (d & b) | (~d & c);
			word = (5 * index + 1) % 16;
		} else if (index < 48) {
			mixed = b ^ c ^ d;
			word = (3 * index + 5) % 16;
		} else {
			mixed = c ^ (b | ~d);
			word = (7 * index) % 16;
		}
		const uint32_t total = a + mixed + constants[index] + words[word];
		a = d;
		d = c;
		c = b;
		b += std::rotl(total, shifts[index]);
	}
	state[0] += a;
	state[1] += b;
	state[2] += c;
	state[3] += d;
}

void put32(uint8_t *at, uint32_t value)
{
	for (int index = 0; index < 4; ++index)
		at[index] = uint8_t(value >> (8 * index));
}

}

// Unlike plain MD5, the bit length leads the final block and the last word carries the byte length doubled plus one.
std::array<uint32_t, 4> container_checksum(std::span<const uint8_t> blob)
{
	std::array<uint32_t, 4> state{0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476};
	const auto data = blob.subspan(20);
	const size_t size = data.size(), whole = size - size % 64;
	for (size_t start = 0; start < whole; start += 64)
		md5_block(state, data.data() + start);
	const size_t rest = size - whole;
	const uint32_t bits = uint32_t(size * 8), last = uint32_t(size * 2) | 1;
	uint8_t block[64]{};
	if (rest >= 56) {
		std::memcpy(block, data.data() + whole, rest);
		block[rest] = 0x80;
		md5_block(state, block);
		std::memset(block, 0, sizeof block);
		put32(block, bits);
		put32(block + 60, last);
		md5_block(state, block);
	} else {
		put32(block, bits);
		std::memcpy(block + 4, data.data() + whole, rest);
		block[4 + rest] = 0x80;
		put32(block + 60, last);
		md5_block(state, block);
	}
	return state;
}

std::vector<uint8_t> container(std::span<const Chunk> chunks)
{
	Writer out;
	out.bytes(std::span(reinterpret_cast<const uint8_t *>("DXBC"), 4));
	for (int index = 0; index < 4; ++index)
		out.u32(0);
	out.u32(1);
	const size_t total_at = out.size();
	out.u32(0);
	out.u32(uint32_t(chunks.size()));
	const size_t offsets_at = out.size();
	for (size_t index = 0; index < chunks.size(); ++index)
		out.u32(0);
	for (size_t index = 0; index < chunks.size(); ++index) {
		out.patch(offsets_at + 4 * index, uint32_t(out.size()));
		out.bytes(std::span(reinterpret_cast<const uint8_t *>(chunks[index].tag.data()), 4));
		out.u32(uint32_t(chunks[index].data.size()));
		out.bytes(chunks[index].data);
	}
	out.patch(total_at, uint32_t(out.size()));
	auto blob = out.take();
	const auto sum = container_checksum(blob);
	for (int index = 0; index < 4; ++index)
		put32(blob.data() + 4 + 4 * index, sum[index]);
	return blob;
}

std::vector<Chunk> read_container(std::span<const uint8_t> blob)
{
	std::vector<Chunk> found;
	if (blob.size() < 32 || std::memcmp(blob.data(), "DXBC", 4) || load32(blob.data() + 24) != blob.size())
		return {};
	const uint32_t count = load32(blob.data() + 28);
	if (blob.size() < 32 + 4 * size_t(count))
		return {};
	for (uint32_t index = 0; index < count; ++index) {
		const uint32_t offset = load32(blob.data() + 32 + 4 * index);
		if (offset > blob.size() || blob.size() - offset < 8)
			return {};
		const uint32_t size = load32(blob.data() + offset + 4);
		if (blob.size() - offset - 8 < size)
			return {};
		Chunk chunk;
		std::memcpy(chunk.tag.data(), blob.data() + offset, 4);
		chunk.data.assign(blob.begin() + offset + 8, blob.begin() + offset + 8 + size);
		found.push_back(std::move(chunk));
	}
	return found;
}

void Writer::u32(uint32_t value)
{
	for (int index = 0; index < 4; ++index)
		data.push_back(uint8_t(value >> (8 * index)));
}

void Writer::f32(float value) { u32(std::bit_cast<uint32_t>(value)); }

void Writer::bytes(std::span<const uint8_t> more) { data.insert(data.end(), more.begin(), more.end()); }

void Writer::text(std::string_view value, bool align_after)
{
	data.insert(data.end(), value.begin(), value.end());
	data.push_back(0);
	if (align_after)
		align(4);
}

void Writer::align(size_t boundary)
{
	while (data.size() % boundary)
		data.push_back(0);
}

void Writer::patch(size_t offset, uint32_t value) { put32(data.data() + offset, value); }

}
