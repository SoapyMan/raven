#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>

namespace raven {

// A Windows single-byte code page other than CP1252: the character of each byte, and Windows' best-fit byte for each character it
// converts, in Unicode order.
struct NativeSingleBytePage {
	uint32_t id;
	const uint16_t *bytes;
	const std::array<uint16_t,2> *best_fit;
	size_t best_fit_count;
};

const NativeSingleBytePage *native_single_byte_page(uint32_t code_page);
std::u16string decode_single_byte(const NativeSingleBytePage &page,std::string_view text);
// The page's byte for a character, best fit unless exact is asked for; nothing when the page has no byte for it.
int encode_single_byte(const NativeSingleBytePage &page,char16_t character,bool exact);

std::string encode_ansi(std::u16string_view text,uint32_t code_page);
std::string encode_utf8(std::u16string_view text,bool replace_invalid=false);

}
