#pragma once

#include <filesystem>
#include <optional>
#include <string_view>

namespace raven {

// Host directory that owns one Windows-visible file tree and registry.
class NativePrefix {
public:
	explicit NativePrefix(std::filesystem::path root);
	// RAVEN_PREFIX, otherwise ~/.local/share/raven/default.
	static NativePrefix from_environment();
	const std::filesystem::path &root() const { return directory; }
	std::filesystem::path registry_file() const { return directory / "registry.dat"; }
	// Maps a Windows path to the prefix: drive letters become drive_<letter>, bare names live in the Windows directory.
	std::optional<std::filesystem::path> resolve(std::string_view windows_path) const;
	// Copies the libraries the runtime ships into System32 and SysWOW64, where programs that open them as files look for them.
	void place_runtime_components(const std::filesystem::path &runtime) const;

private:
	std::filesystem::path directory;
};

}
