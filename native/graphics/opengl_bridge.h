#pragma once

#include <memory>
#include <span>
#include <string_view>

namespace raven {

class ApiRegistry;
class DesktopObjects;
class ModuleSet;
class NativeProcess;
class NativeThreads;
class NativeWindows;

class OpenGLBridge {
public:
	OpenGLBridge(NativeProcess &process, ModuleSet &modules, DesktopObjects &objects, NativeWindows &windows);
	~OpenGLBridge();
	static bool enabled();
	// Whether RAVEN_NATIVE_OPENGL=1 asked for the bridge rather than leaving it the default.
	static bool requested();
	static bool served_api(std::string_view name);
	static std::span<const std::string_view> exports();
	void register_api(ApiRegistry &registry, NativeThreads &threads);

private:
	struct State;
	std::unique_ptr<State> state;
};

}
