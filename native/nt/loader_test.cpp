#include "loader.h"
#include "providers.h"
#include "environment.h"

#include <algorithm>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <signal.h>
#include <stdexcept>
#include <sys/mman.h>

static std::vector<uint8_t> read_file(const std::filesystem::path &path)
{
	std::ifstream file(path, std::ios::binary | std::ios::ate);
	if (!file || file.tellg() <= 0 || file.tellg() > 1024 * 1024)
		throw std::runtime_error("cannot read DLL lifecycle fixture");
	std::vector<uint8_t> bytes(static_cast<size_t>(file.tellg()));
	file.seekg(0);
	if (!file.read(reinterpret_cast<char *>(bytes.data()), static_cast<std::streamsize>(bytes.size())))
		throw std::runtime_error("truncated DLL lifecycle fixture");
	return bytes;
}

static void check(bool condition, const char *message)
{
	if (!condition)
		throw std::runtime_error(message);
}

static uint32_t field(const raven::ModuleSet &modules, const std::string &name, const std::string &symbol)
{
	auto &module = *modules.all().at(name);
	const auto address = modules.resolve({name, symbol, 0, false, 0});
	const auto data = module.loaded.data().subspan(address - module.loaded.base(), 4);
	uint32_t result = 0;
	for (size_t byte = 0; byte < data.size(); ++byte)
		result |= uint32_t(data[byte]) << (byte * 8);
	return result;
}

static uint64_t pointer(raven::NativeProcess &process, uint64_t address)
{
	const auto bytes = process.read_memory(address, 8);
	uint64_t value = 0;
	for (size_t index = 0; index < bytes.size(); ++index)
		value |= uint64_t(bytes[index]) << (index * 8);
	return value;
}

static void dynamic_lists(const std::filesystem::path &directory, const std::string &bootstrap)
{
	raven::ModuleSet modules;
	auto &entry = modules.add("client.exe", read_file(directory / "client.exe"));
	entry.imports.clear();
	entry.loaded.data()[entry.image.entry] = 0xcc;
	entry.loaded.data()[entry.image.entry + 1] = 0xc3;
	raven::LoadedImage *images[] = {&entry.loaded};
	raven::NativeProcess process(images, bootstrap, std::chrono::seconds(10));
	raven::NativeEnvironment environment(process, entry.loaded.base(), 1, 1);
	raven::NativeLoaderData loader(process, environment.peb(), modules, entry);
	const auto initial_node = pointer(process, loader.address() + 0x10);
	const auto initial_fields = process.read_memory(initial_node + 0x30, 0xf0);
	const auto rejected = [&](const auto &operation) {
		bool failed = false;
		try { operation(); } catch (const std::runtime_error &) { failed = true; }
		check(failed, "invalid dynamic loader list operation succeeded");
	};
	const auto list = [&](size_t head_offset, size_t member) {
		const uint64_t head = loader.address() + head_offset;
		std::vector<uint64_t> result;
		uint64_t previous = head;
		uint64_t current = pointer(process, head);
		while (current != head) {
			check(result.size() < 10 && pointer(process, current + 8) == previous,
				"dynamic loader list backward link differs");
			result.push_back(pointer(process, current - member + 0x30));
			previous = current;
			current = pointer(process, current);
		}
		check(pointer(process, head + 8) == previous, "dynamic loader tail link differs");
		return result;
	};
	process.add_api_trap(entry.loaded.base() + entry.image.entry);
	const uint64_t arguments[] = {17, 23};
	check(process.call(entry.loaded.base() + entry.image.entry, arguments, std::chrono::seconds(10)).stop == raven::NativeStop::api,
		"dynamic loader list fixture did not reach API suspension");
	const auto before = process.context();
	auto &base = modules.add("base.dll", read_file(directory / "base.dll"));
	auto &dependent = modules.add("dependent.dll", read_file(directory / "dependent.dll"));
	rejected([&] { loader.add(base); });
	process.map_image(base.loaded);
	process.map_image(dependent.loaded);
	loader.add(base);
	loader.add(dependent);
	rejected([&] { loader.add(base); });
	rejected([&] { loader.remove(entry); });
	const std::vector<uint64_t> expected{entry.loaded.base(), base.loaded.base(), dependent.loaded.base()};
	check(list(0x10, 0) == expected && list(0x20, 0x10) == expected && list(0x30, 0x20).empty(),
		"new DLL was missing or initialized before notification");
	loader.initialized(base);
	rejected([&] { loader.initialized(base); });
	const auto old_loader = process.read_memory(environment.peb() + 0x18, 8);
	process.write_memory(environment.peb() + 0x18, std::vector<uint8_t>(8));
	rejected([&] { loader.initialized(dependent); });
	process.write_memory(environment.peb() + 0x18, old_loader);
	const auto old_head = process.read_memory(loader.address() + 0x10, 16);
	process.write_memory(loader.address() + 0x10, std::vector<uint8_t>(16));
	rejected([&] { loader.initialized(dependent); });
	process.write_memory(loader.address() + 0x10, old_head);
	const auto dependent_node = pointer(process, loader.address() + 0x18);
	const auto dependent_fields = process.read_memory(dependent_node, 0x120);
	process.protect_memory(loader.address(), 4096, PROT_READ);
	rejected([&] { loader.initialized(dependent); });
	process.protect_memory(loader.address(), 4096, PROT_READ | PROT_WRITE);
	check(process.read_memory(dependent_node, 0x120) == dependent_fields &&
		list(0x30, 0x20) == std::vector<uint64_t>{base.loaded.base()}, "failed list publication was not rolled back");
	loader.initialized(dependent);
	check(list(0x30, 0x20) == std::vector<uint64_t>{base.loaded.base(), dependent.loaded.base()},
		"dynamic initialization list order differs");
	loader.remove(base);
	process.unmap_image(base.loaded.base());
	check(list(0x10, 0) == std::vector<uint64_t>{entry.loaded.base(), dependent.loaded.base()} &&
		list(0x30, 0x20) == std::vector<uint64_t>{dependent.loaded.base()}, "middle DLL removal broke links");
	loader.remove(dependent);
	process.unmap_image(dependent.loaded.base());
	rejected([&] { process.read_memory(dependent_node, 1); });
	rejected([&] { loader.remove(dependent); });
	check(list(0x10, 0) == std::vector<uint64_t>{entry.loaded.base()} && list(0x30, 0x20).empty() &&
		pointer(process, environment.peb() + 0x18) == loader.address() &&
		pointer(process, loader.address() + 0x10) == initial_node &&
		process.read_memory(initial_node + 0x30, 0xf0) == initial_fields,
		"dynamic lists replaced initial loader pointers or metadata");
	const auto after = process.context();
	check(after.registers.rip == before.registers.rip && after.registers.rsp == before.registers.rsp &&
		process.api_arguments(2) == std::vector<uint64_t>{17, 23}, "dynamic list operations lost pending API context");
	process.return_api(88);
	check(process.resume(std::chrono::seconds(10)).value == 88, "dynamic list operations lost guest return");
	std::cout << "Dynamic PEB list publication, stable nodes, initialization transitions, removal and rollback passed\n";
}

int main(int argc, char **argv)
{
	try {
		if (argc != 3)
			throw std::runtime_error("bootstrap and lifecycle fixture directory required");
		const std::filesystem::path directory(argv[2]);
		dynamic_lists(directory, argv[1]);
		for (const std::string extra : {"", "exit", "reject.dll", "fault.dll", "loop.dll"}) {
			const bool explicit_exit = extra == "exit";
			raven::ModuleSet modules;
			raven::PEModule *entry = nullptr;
			for (const std::string name : std::vector<std::string>{"client.exe", "dependent.dll", "base.dll", explicit_exit ? "" : extra}) {
				if (name.empty())
					continue;
				auto bytes = read_file(directory / name);
				const auto base = raven::PEImage(bytes).image_base;
				auto &module = modules.add(name, std::move(bytes), base);
				if (!entry)
					entry = &module;
			}
			if (explicit_exit) {
				const auto address = modules.resolve({"client.exe", "exit_requested", 0, false, 0});
				entry->loaded.data()[address - entry->loaded.base()] = 1;
			}
			// The looping DLL must still be reached after base.dll and dependent.dll attach, which can take most of a second on a loaded host.
			const auto timeout = std::chrono::milliseconds(extra == "loop.dll" ? 2000 : 10000);
			if (extra == "reject.dll") {
				bool rejected = false;
				try { raven::run_native_process(modules, *entry, argv[1], timeout); }
				catch (const std::runtime_error &error) { rejected = std::string(error.what()) == "DLL_PROCESS_ATTACH failed: reject.dll"; }
				check(rejected, "failed DLL attach did not abort startup");
				check(field(modules, "base.dll", "shutdown_state") == 0, "DLL attach rollback observed process shutdown");
				check(field(modules, "base.dll", "base_state") == 1125634 &&
					field(modules, "dependent.dll", "dependent_state") == 210 &&
					field(modules, "reject.dll", "reject_state") == 510, "DLL failure rollback order or reserved argument differs");
			} else {
				const auto result = raven::run_native_process(modules, *entry, argv[1], timeout);
				if (extra.empty() || explicit_exit) {
					check(result.stop == (explicit_exit ? raven::NativeStop::exited : raven::NativeStop::returned) && result.value == 0,
						"DLL attach order failed the executable workflow");
					check(field(modules, "base.dll", "shutdown_state") == 1, "DLL process detach did not observe shutdown");
					check(field(modules, "base.dll", "base_state") == 11234 &&
						field(modules, "dependent.dll", "dependent_state") == 210, "DLL process detach order differs");
					auto &base = *modules.all().at("base.dll");
					auto &dependent = *modules.all().at("dependent.dll");
					const auto precedes = [](const auto &order, const auto *first, const auto *second) {
						return std::find(order.begin(), order.end(), first) < std::find(order.begin(), order.end(), second);
					};
					auto order = raven::initialization_order(modules, *entry);
					check(precedes(order, &base, &dependent) && precedes(order, &dependent, entry), "static dependency initialization order differs");
					// Exercise activated forwarder edges independently of guest execution.
					base.exports.push_back({500, 1, {"Through"}, "dependent.DependentState"});
					dependent.imports.clear();
					entry->imports = {{"base.dll", "Through", 0, false, 0}};
					check(modules.resolution_path(entry->imports.front()) == std::vector<const raven::PEModule *>{&base, &dependent}, "forwarder resolution path differs");
					order = raven::initialization_order(modules, *entry);
					check(precedes(order, &dependent, &base) && precedes(order, &base, entry), "forwarded dependency initializes after its facade");
					dependent.imports = {{"base.dll", "Query", 0, false, 0}};
					order = raven::initialization_order(modules, *entry);
					check(order.size() == modules.all().size() && std::count(order.begin(), order.end(), &base) == 1 &&
						std::count(order.begin(), order.end(), &dependent) == 1, "cyclic dependencies initialize more than once");
				} else {
					check(result.stop == (extra == "loop.dll" ? raven::NativeStop::timeout : raven::NativeStop::fault), "DLL fault or timeout produced apparent startup success");
					if (extra == "fault.dll")
						check(result.signal == SIGILL, "DLL instruction fault signal differs");
					check(field(modules, "base.dll", "base_state") == 1125, "DLL fault/timeout ran extra guest cleanup code");
				}
			}
			check(field(modules, "client.exe", "entered") == (extra.empty() || explicit_exit ? 1U : 0U), "executable entry ran after DLL initialization failed");
		}
		std::cout << "Compiled DLL dependency attach, reverse detach, rejected attach rollback, fault/timeout and blocked EXE entry passed\n";
		return 0;
	} catch (const std::exception &error) {
		std::cerr << error.what() << '\n';
		return 1;
	}
}
