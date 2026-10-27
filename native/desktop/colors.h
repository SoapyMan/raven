#pragma once

#include <array>
#include <cstdint>

namespace raven {

using DesktopColors=std::array<uint32_t,31>;

// Pinned Wine palette profile, except COLOR_HOTLIGHT, which programs use for link text and so gets the usual link blue.
// Host/theme synchronization remains separate.
inline constexpr DesktopColors desktop_colors{
	0xffffffU,0x956f25U,0xfa9632U,0x808080U,0xffffffU,0xffffffU,
	0x9e9e9eU,0x000000U,0x000000U,0x000000U,0xffffffU,0xffffffU,
	0x808080U,0xfa9630U,0xffffffU,0xf5f5f5U,0xa6a6a6U,0x6a6a6aU,
	0x000000U,0xc8c8c8U,0xffffffU,0x6a6a6aU,0xe3e3e3U,0x000000U,
	0xffffffU,0xffffffU,0xcc6600U,0xfa9632U,0x808080U,0xfa9630U,
	0xffffffU
};

}
