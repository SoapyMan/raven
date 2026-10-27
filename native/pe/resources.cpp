#include "resources.h"

#include <algorithm>
#include <functional>
#include <optional>
#include <set>
#include <stdexcept>

namespace raven {

std::vector<PEResource> read_resources(PEDirectory directory,
	std::span<const uint8_t> bytes, uint32_t image_size, std::vector<std::pair<size_t, size_t>> *read)
{
	if (!directory.address && !directory.size)
		return {};
	if (!directory.address || !directory.size || bytes.size() != directory.size ||
		directory.address > image_size || directory.size > image_size - directory.address)
		throw std::runtime_error("invalid PE resource directory extent");
	const auto range = [&](size_t offset, size_t size) {
		if (offset > bytes.size() || size > bytes.size() - offset)
			throw std::runtime_error("PE resource metadata exceeds directory");
		if (read)
			read->emplace_back(offset, size);
	};
	const auto number = [&](size_t offset, size_t width) {
		range(offset, width);
		uint32_t value = 0;
		for (size_t index = 0; index < width; ++index)
			value |= uint32_t(bytes[offset + index]) << (index * 8);
		return value;
	};
	const auto key = [&](uint32_t value) -> ResourceKey {
		if (!(value & 0x80000000U))
			return value;
		const size_t offset = value & 0x7fffffffU;
		if (offset % 2)
			throw std::runtime_error("unaligned PE resource name");
		const auto count = number(offset, 2);
		range(offset + 2, size_t(count) * 2);
		std::u16string text;
		text.reserve(count);
		for (size_t index = 0; index < count; ++index)
			text += static_cast<char16_t>(number(offset + 2 + index * 2, 2));
		return text;
	};
	std::vector<PEResource> resources;
	std::set<uint32_t> visited;
	size_t entries = 0;
	size_t result_bytes = 0;
	std::function<void(uint32_t, unsigned, ResourceKey, ResourceKey)> walk;
	walk = [&](uint32_t offset, unsigned depth, ResourceKey type, ResourceKey name) {
		if (offset % 4 || !visited.insert(offset).second)
			throw std::runtime_error("unaligned or reused PE resource directory");
		range(offset, 16);
		const auto named = number(size_t(offset) + 12, 2);
		const auto count = named + number(size_t(offset) + 14, 2);
		range(size_t(offset) + 16, size_t(count) * 8);
		// Every entry takes eight bytes of the directory, so the directory's own size bounds them; large resource libraries hold
		// hundreds of thousands.
		if (entries + count > bytes.size() / 8)
			throw std::runtime_error("PE resource entries exceed policy limit");
		entries += count;
		std::optional<ResourceKey> previous;
		for (size_t index = 0; index < count; ++index) {
			const size_t position = size_t(offset) + 16 + index * 8;
			const auto raw_name = number(position, 4);
			if (bool(raw_name & 0x80000000U) != (index < named))
				throw std::runtime_error("PE resource name and ID partitions differ");
			auto identity = key(raw_name);
			if (previous && previous->index() == identity.index() && !(*previous < identity))
				throw std::runtime_error("PE resource entries are unordered or duplicated");
			previous = identity;
			const auto child = number(position + 4, 4);
			if (depth < 2) {
				if (!(child & 0x80000000U))
					throw std::runtime_error("PE resource tree ends before language");
				walk(child & 0x7fffffffU, depth + 1, depth == 0 ? identity : type,
					depth == 1 ? identity : name);
				continue;
			}
			if ((child & 0x80000000U) || !std::holds_alternative<uint32_t>(identity) || child % 4)
				throw std::runtime_error("invalid PE resource language leaf");
			range(child, 16);
			const auto data = number(child, 4);
			const auto size = number(size_t(child) + 4, 4);
			if (data > image_size || size > image_size - data)
				throw std::runtime_error("PE resource payload exceeds image");
			const auto key_size = [](const ResourceKey &value) {
				const auto *text = std::get_if<std::u16string>(&value);
				return text ? text->size() * 2 : size_t(0);
			};
			const size_t record_size = sizeof(PEResource) + key_size(type) + key_size(name);
			if (record_size > 64 * 1024 * 1024 - result_bytes)
				throw std::runtime_error("PE resource identities exceed policy limit");
			result_bytes += record_size;
			resources.push_back({type, name, std::get<uint32_t>(identity), directory.address + child,
				data, size, number(size_t(child) + 8, 4)});
		}
	};
	walk(0, 0, uint32_t(0), uint32_t(0));
	return resources;
}

std::vector<PEResource> PEImage::resources() const
{
	const auto directory = directories[2];
	if (!directory.address && !directory.size)
		return {};
	auto result = read_resources(directory, file_span(directory.address, directory.size), image_size);
	for (const auto &resource : result)
		file_span(resource.data_address, resource.size);
	return result;
}

}
