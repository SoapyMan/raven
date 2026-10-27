#include "api.h"
#include "nt/providers.h"
#include "pe/resources.h"
#include "icon_data.h"

#include <filesystem>
#include <fstream>
#include <iostream>
#include <stdexcept>
#include <sys/mman.h>

static void check(bool condition, const char *message)
{
	if (!condition)
		throw std::runtime_error(message);
}

static std::vector<uint8_t> read_file(const std::filesystem::path &path)
{
	std::ifstream file(path, std::ios::binary | std::ios::ate);
	check(bool(file) && file.tellg() > 0 && file.tellg() < 1024 * 1024 * 1024, "invalid desktop fixture");
	std::vector<uint8_t> bytes(static_cast<size_t>(file.tellg()));
	file.seekg(0);
	check(bool(file.read(reinterpret_cast<char *>(bytes.data()), static_cast<std::streamsize>(bytes.size()))), "cannot read desktop fixture");
	return bytes;
}

static uint64_t number(std::span<const uint8_t> bytes, size_t offset)
{
	uint64_t value = 0;
	for (size_t index = 0; index < 8; ++index)
		value |= uint64_t(bytes[offset + index]) << (index * 8);
	return value;
}

int main(int argc, char **argv)
{
	try {
		check(argc == 5, "bootstrap, desktop fixtures, application and output directory required");
		const std::filesystem::path directory(argv[2]);
		{
			raven::ModuleSet modules;
			auto &entry = modules.add("client.exe", read_file(directory / "client.exe"));
			unsigned loads = 0;
			const auto source = [&](std::string_view name) -> std::optional<std::vector<uint8_t>> {
				check(name == "icons.dll", "icon workflow requested an unexpected DLL");
				++loads;
				return read_file(directory / "icons.dll");
			};
			const auto result = raven::run_native_process(modules, entry, argv[1], std::chrono::seconds(2), source);
			check(result.stop == raven::NativeStop::returned && result.value == 0, "SDK icon ownership workflow failed");
			const auto phase = modules.resolve({"client.exe", "phase", 0, false, 0}) - entry.loaded.base();
			check(entry.loaded.data()[size_t(phase)] == 6 && loads == 2 && !modules.all().contains("icons.dll"),
				"SDK icon workflow did not survive resource module unload");
		}
		raven::ModuleSet modules;
		auto &entry = modules.add("client.exe", read_file(directory / "client.exe"));
		auto &user = modules.add("user32.dll", raven::runtime_provider("user32.dll", 0x180000000ULL, raven::NativeDesktop::user_exports()));
		auto &gdi = modules.add("gdi32.dll", raven::runtime_provider("gdi32.dll", 0x180010000ULL, raven::NativeDesktop::gdi_exports()));
		auto &controls = modules.add("comctl32.dll", raven::runtime_provider("comctl32.dll", 0x180020000ULL, raven::NativeDesktop::control_exports()));
		auto &resource_module = modules.add("icons.dll", read_file(directory / "icons.dll"));
		raven::LoadedImage *images[] = {&entry.loaded, &user.loaded, &gdi.loaded, &controls.loaded, &resource_module.loaded};
		raven::NativeProcess process(images, argv[1], std::chrono::seconds(2));
		for (const auto &[provider, name] : {std::pair{&user, "user32.dll"}, {&gdi, "gdi32.dll"}, {&controls, "comctl32.dll"}})
			for (const auto &symbol : provider->exports)
				if (!symbol.names.empty() && symbol.forwarder.empty())
					process.add_api_trap(raven::api_trap_address(*provider, name, symbol.names.at(0), symbol.address));
		raven::NativeEnvironment environment(process, entry.loaded.base(), 1, 1);
		raven::DesktopObjects objects;
		{
			raven::DesktopObjects titles(sizeof(raven::DesktopWindow)+6);
			const auto handle=titles.add(raven::DesktopWindow{1,2,u"",0,0,1,1});
			check(handle && titles.set_title(handle,u"abc") && titles.bytes()==sizeof(raven::DesktopWindow)+6,
				"window title budget was not charged");
			check(!titles.set_title(handle,u"abcd") && titles.window(handle)->title==u"abc",
				"rejected title update damaged owned text");
			check(titles.set_title(handle,u"a") && titles.bytes()==sizeof(raven::DesktopWindow)+2 &&
				titles.erase(handle) && !titles.bytes(),"window title lifetime leaked budget");
		}
		{
			raven::DesktopObjects classes;
			const auto atom=classes.register_class({"owned",1,2});
			check(atom && classes.find_class(1,"owned")==atom && !classes.register_class({"owned",1,3}),
				"desktop class identity or duplicate ownership differs");
			const auto bytes=classes.bytes();
			const auto window=classes.add(raven::DesktopWindow{atom,2,u"title",1,2,3,4});
			check(window && classes.window(window) && !classes.bitmap(window) && !classes.dc(window) &&
				classes.unregister_class(atom)==1412,"window kind or live class protection differs");
			check(classes.erase(window) && classes.bytes()==bytes && !classes.unregister_class(atom) && !classes.bytes() &&
				classes.unregister_class(atom)==1411,"class/window resource lifetime leaked state");
			raven::DesktopObjects budget(sizeof(raven::DesktopClass)+1);
			const auto retained=budget.register_class({"x",1,2});
			check(retained && !budget.add(raven::DesktopWindow{retained,2,u"",0,0,0,0}) &&
				budget.window_class(retained) && !budget.unregister_class(retained),"window budget damaged class ownership");
		}
		raven::NativeResources resources_api(process,environment,modules,entry);
		raven::NativeDesktop desktop(process, environment, objects, resources_api);
		const auto address = [&](const char *name) {
			const auto module = std::string_view(name) == "CopyIcon" || std::string_view(name) == "DestroyIcon" ||
				std::string_view(name) == "GetIconInfo" || std::string_view(name) == "CreateIconFromResourceEx" ||
				std::string_view(name) == "DrawIconEx" || std::string_view(name) == "LookupIconIdFromDirectoryEx" ? "user32.dll" : "gdi32.dll";
			return modules.resolve({std::string_view(name) == "LoadIconWithScaleDown" ? "comctl32.dll" : module, name, 0, false, 0});
		};
		const auto api = [&](const char *name, std::initializer_list<uint64_t> args) {
			check(process.call(address(name), std::span(args.begin(), args.size()), std::chrono::seconds(1)).stop == raven::NativeStop::api,
				"desktop API did not trap");
			check(desktop.dispatch(name), "desktop API not dispatched");
			const auto result = process.resume(std::chrono::seconds(1));
			check(result.stop == raven::NativeStop::returned, "desktop API did not return");
			return result.value;
		};
		const auto rejected = [&](const char *name, std::initializer_list<uint64_t> args, bool input = false) {
			const size_t count = objects.count();
			const size_t used = objects.bytes();
			check(process.call(address(name), std::span(args.begin(), args.size()), std::chrono::seconds(1)).stop == raven::NativeStop::api,
				"desktop pointer negative did not trap");
			std::string failure;
			try { desktop.dispatch(name); } catch (const std::runtime_error &error) { failure = error.what(); }
			check(failure.find(input || std::string_view(name) == "CreateIconFromResourceEx" ||
				std::string_view(name) == "LookupIconIdFromDirectoryEx" ? "readable" : "writable") != failure.npos,
				"desktop pointer negative failed for a different reason");
			check(objects.count() == count && objects.bytes() == used, "failed guest access leaked desktop objects");
			process.return_api(0);
			check(process.resume(std::chrono::seconds(1)).stop == raven::NativeStop::returned, "desktop negative lost API context");
		};
		const auto buffer = process.map_memory(4096, PROT_READ | PROT_WRITE);
		const auto resource_base = resource_module.loaded.base();
		check(api("LoadIconWithScaleDown", {resource_base,201,16,16,0}) == 0x80070057U &&
			api("LoadIconWithScaleDown", {resource_base,201,uint32_t(-1),16,buffer}) == 0x80070057U &&
			!number(process.read_memory(buffer,8),0), "invalid icon load arguments succeeded");
		check(api("LoadIconWithScaleDown", {0,201,16,16,buffer}) == 0x80004001U &&
			api("LoadIconWithScaleDown", {resource_base,0,16,16,buffer}) == 0x80070057U &&
			api("LoadIconWithScaleDown", {1,201,16,16,buffer}) == 0x80070006U &&
			api("LoadIconWithScaleDown", {resource_base,999,16,16,buffer}) == 0x80070716U &&
			!number(process.read_memory(buffer,8),0) && !objects.count(), "failed icon load published state");
		rejected("LoadIconWithScaleDown", {resource_base,201,16,16,0x400000000000ULL});
		process.protect_memory(buffer,4096,PROT_READ);
		rejected("LoadIconWithScaleDown", {resource_base,201,16,16,buffer});
		process.protect_memory(buffer,4096,PROT_READ | PROT_WRITE);
		for (const auto size : {16U,20U,40U,0U}) {
			check(api("LoadIconWithScaleDown", {resource_base,201,size,size,buffer}) == 0, "resource icon load failed");
			const auto loaded = number(process.read_memory(buffer,8),0);
			const auto *image = objects.icon(loaded);
			check(image && image->image.color.width == (size ? size : 16) &&
				image->image.color.height == (size ? size : 16) && image->image.color.rgba[0] == (size==20 || size==40 ? 32 : 16),
				"icon load size or documented source preference differs");
			check(api("DestroyIcon",{loaded}) && !objects.count(), "loaded resource icon leaked");
		}
		check(api("LoadIconWithScaleDown", {resource_base,201,8193,8193,buffer}) == 0x80070057U &&
			!number(process.read_memory(buffer,8),0) && !objects.count(), "oversized load published an icon");
		check(!api("LookupIconIdFromDirectoryEx", {buffer, 1, 16, 16, 0}) && environment.last_error() == 13,
			"malformed group was accepted");
		check(!api("LookupIconIdFromDirectoryEx", {buffer, 1, uint32_t(-1), 16, 0}) && environment.last_error() == 87,
			"negative lookup size was accepted");
		check(!api("LookupIconIdFromDirectoryEx", {buffer, 0, 16, 16, 0}) && environment.last_error() == 120 &&
			!api("LookupIconIdFromDirectoryEx", {buffer, 1, 16, 16, 2}) && environment.last_error() == 120,
			"unsupported cursor or lookup flags succeeded");
		check(process.call(address("LookupIconIdFromDirectoryEx"), std::array<uint64_t,5>{0x400000000000ULL,1,16,16,0},
			std::chrono::seconds(1)).stop == raven::NativeStop::api, "lookup pointer negative did not trap");
		std::string lookup_failure;
		try { desktop.dispatch("LookupIconIdFromDirectoryEx"); } catch (const std::runtime_error &error) { lookup_failure = error.what(); }
		check(lookup_failure.find("readable") != lookup_failure.npos, "lookup pointer failed for another reason");
		process.return_api(0);
		check(process.resume(std::chrono::seconds(1)).stop == raven::NativeStop::returned && !objects.count(),
			"lookup pointer failure lost caller or allocated desktop state");
		process.write_memory(buffer + 4090, std::array<uint8_t,6>{0,0,1,0,255,255});
		rejected("LookupIconIdFromDirectoryEx", {buffer + 4090,1,16,16,0});
		process.write_memory(buffer, color_icon);
		const auto icon = api("CreateIconFromResourceEx", {buffer, sizeof(color_icon), 1, 0x30000, 3, 2, 0});
		check(icon && objects.icon(icon) && objects.count() == 1, "icon has no owned image");
		process.write_memory(buffer, std::vector<uint8_t>(sizeof(color_icon), 0));
		check(objects.icon(icon)->image.color.rgba[0] == 255, "icon retained borrowed resource bytes");
		check(api("GetIconInfo", {icon, buffer + 512}), "icon info unavailable");
		const auto info = process.read_memory(buffer + 512, 32);
		const auto mask = number(info, 16), color = number(info, 24);
		check(mask && color && objects.bitmap(mask) && objects.bitmap(color), "bitmap copies have no desktop owner");
		check(api("GetIconInfo", {icon, buffer + 544}), "repeated icon info unavailable");
		const auto again = process.read_memory(buffer + 544, 32);
		check(number(again, 16) != mask && number(again, 24) != color, "GetIconInfo reused caller-owned bitmap handles");
		check(api("DeleteObject", {number(again, 16)}) && api("DeleteObject", {number(again, 24)}), "repeated bitmap copies did not release");
		rejected("GetIconInfo", {icon, 0x400000000000ULL});
		process.protect_memory(buffer, 4096, PROT_READ);
		rejected("GetIconInfo", {icon, buffer});
		rejected("GetObjectW", {color, 32, buffer});
		rejected("GetBitmapBits", {color, 24, buffer});
		process.protect_memory(buffer, 4096, PROT_READ | PROT_WRITE);
		check(!api("DeleteObject", {icon}) && !api("DestroyIcon", {color}) && !api("GetObjectW", {icon, 32, buffer}),
			"desktop handle crossed object kind");
		check(!api("CopyIcon", {mask}) && environment.last_error() == 1402, "bitmap copied as icon");
		check(api("DestroyIcon", {icon}) && objects.bitmap(mask) && objects.bitmap(color), "icon destruction removed bitmap copies");
		check(api("DeleteObject", {mask}) && api("DeleteObject", {color}) && objects.count() == 0 && objects.bytes() == 0,
			"owned desktop objects leaked");
		process.write_memory(buffer, color_icon);
		const auto resized = api("CreateIconFromResourceEx", {buffer, sizeof(color_icon), 1, 0x30000, 4, 2, 0});
		check(resized && objects.icon(resized)->image.color.width == 4 && objects.icon(resized)->image.color.height == 2 &&
			api("DestroyIcon",{resized}) && objects.count() == 0,"guest resized icon geometry or lifetime differs");
		const auto one_axis = api("CreateIconFromResourceEx",{buffer,sizeof(color_icon),1,0x30000,0,1,0});
		check(one_axis && objects.icon(one_axis)->image.color.width == 3 && objects.icon(one_axis)->image.color.height == 1 &&
			api("DestroyIcon",{one_axis}),"zero desired axis did not retain source dimension");
		check(!api("CreateIconFromResourceEx", {buffer, sizeof(color_icon), 1, 0x30000, 8193, 2, 0}) && environment.last_error() == 87 &&
			!api("CreateIconFromResourceEx", {buffer, sizeof(color_icon), 1, 0x30000, 8192, 8192, 0}) && environment.last_error() == 87 && !objects.count(),
			"oversized output created an icon");
		// A cursor's resource is its hot spot, two words, then the same bitmap.
		std::vector<uint8_t> cursor_resource{1, 0, 2, 0};
		cursor_resource.insert(cursor_resource.end(), std::begin(color_icon), std::end(color_icon));
		process.write_memory(buffer, cursor_resource);
		const auto cursor = api("CreateIconFromResourceEx", {buffer, cursor_resource.size(), 0, 0x30000, 0, 0, 0});
		check(cursor && objects.icon(cursor)->cursor && objects.icon(cursor)->hotspot_x == 1 && objects.icon(cursor)->hotspot_y == 2 &&
			objects.icon(cursor)->image.color.width == 3 && api("DestroyIcon", {cursor}) && !objects.count(), "cursor resource differs");
		process.write_memory(buffer, color_icon);
		check(!api("CreateIconFromResourceEx", {buffer, sizeof(color_icon), 1, 0x30000, 0, 0, 0x40}) && environment.last_error() == 120,
			"unsupported metrics silently succeeded");
		rejected("CreateIconFromResourceEx", {0x400000000000ULL, sizeof(color_icon), 1, 0x30000, 0, 0, 0});
		process.write_memory(buffer, std::vector<uint8_t>(sizeof(color_icon), 0));
		check(!api("CreateIconFromResourceEx", {buffer, sizeof(color_icon), 1, 0x30000, 0, 0, 0}) && environment.last_error() == 13 && !objects.count(),
			"malformed icon published an object");
		raven::DesktopObjects limited(8);
		check(!limited.add(raven::DesktopBitmap{3, 2, 32, std::vector<uint8_t>(24)}) && limited.count() == 0 && limited.bytes() == 0,
			"desktop storage policy did not reject oversize object");
		raven::DesktopObjects budget(35);
		raven::NativeDesktop bounded(process, environment, budget, resources_api);
		const auto bounded_api = [&](const char *name, std::initializer_list<uint64_t> args) {
			check(process.call(address(name), std::span(args.begin(), args.size()), std::chrono::seconds(1)).stop == raven::NativeStop::api &&
				bounded.dispatch(name), "bounded desktop API did not dispatch");
			const auto result = process.resume(std::chrono::seconds(1));
			check(result.stop == raven::NativeStop::returned, "bounded desktop API did not return");
			return result.value;
		};
		process.write_memory(buffer, color_icon);
		const auto retained = bounded_api("CreateIconFromResourceEx", {buffer, sizeof(color_icon), 1, 0x30000, 0, 0, 0});
		check(retained && budget.count() == 1 && budget.bytes() == 30, "bounded icon was not published");
		check(!bounded_api("GetIconInfo", {retained, buffer + 512}) && environment.last_error() == 8 &&
			budget.count() == 1 && budget.bytes() == 30, "partial bitmap allocation was not rolled back");
		check(!bounded_api("CopyIcon", {retained}) && environment.last_error() == 8 && budget.count() == 1,
			"copy exceeded desktop storage budget");
		check(!bounded_api("CreateIconFromResourceEx",{buffer,sizeof(color_icon),1,0x30000,2,1,0}) &&
			environment.last_error() == 8 && budget.count() == 1 && budget.bytes() == 30,
			"resized icon exceeded retained storage budget");
		check(bounded_api("DestroyIcon", {retained}) && budget.bytes() == 0 && budget.count() == 0,
			"bounded desktop icon did not release storage");
		check(!desktop.dispatch("Unimplemented"), "unknown desktop API accepted");
		auto &application = modules.add("notepad++.exe", read_file(argv[3]));
		process.map_image(application.loaded);
		const auto output = process.map_memory(1024 * 1024, PROT_READ | PROT_WRITE);
		const std::filesystem::path evidence(argv[4]);
		std::filesystem::create_directories(evidence);
		const auto resources = application.image.resources();
		const auto section_header = [&](uint32_t width, uint32_t height) {
			std::array<uint8_t,40> header{};
			const auto put = [&](size_t at, uint32_t value) {
				for (size_t byte = 0; byte < 4; ++byte)
					header[at+byte] = uint8_t(value >> (byte*8));
			};
			put(0,40); put(4,width); put(8,uint32_t(-int32_t(height)));
			header[12] = 1; header[14] = 32;
			process.write_memory(buffer+2048,header);
		};
		section_header(3,2);
		check(!api("CreateCompatibleDC",{1}) && !objects.count(),"invalid source DC created state");
		rejected("CreateDIBSection",{0,buffer+2048,0,0x400000000000ULL,0,0});
		rejected("CreateDIBSection",{0,0x400000000000ULL,0,buffer+128,0,0},true);
		section_header(16385,2);
		check(!api("CreateDIBSection",{0,buffer+2048,0,buffer+128,0,0}) && environment.last_error()==87 &&
			!number(process.read_memory(buffer+128,8),0) && !objects.count(),"oversized section created state");
		section_header(3,2);
		process.write_memory(buffer+2048+14,std::array<uint8_t,2>{24,0});
		{
			const auto section24=api("CreateDIBSection",{0,buffer+2048,0,buffer+128,0,0});
			check(section24 && objects.bitmap(section24)->depth==24 && objects.bitmap(section24)->stride==12 && objects.bitmap(section24)->dib_section,
				"24-bit section was not created with its own row layout");
			check(api("DeleteObject",{section24}),"24-bit section could not be deleted");
		}
		process.write_memory(buffer+2048+14,std::array<uint8_t,2>{3,0});
		check(!api("CreateDIBSection",{0,buffer+2048,0,buffer+128,0,0}) && environment.last_error()==87 && !objects.count(),
			"invalid section depth succeeded");
		section_header(3,2);
		process.protect_memory(buffer,4096,PROT_READ);
		rejected("CreateDIBSection",{0,buffer+2048,0,buffer+128,0,0});
		process.protect_memory(buffer,4096,PROT_READ | PROT_WRITE);
		check(!api("CreateDIBSection",{0,buffer+2048,2,buffer+128,0,0}) && environment.last_error()==120 &&
			!api("CreateDIBSection",{0,buffer+2048,0,buffer+128,1,0}) && environment.last_error()==6 && !objects.count(),
			"unsupported section mode or a section that is no section succeeded");
		check(!bounded_api("CreateDIBSection",{0,buffer+2048,0,buffer+128,0,0}) && environment.last_error()==8 &&
			!number(process.read_memory(buffer+128,8),0) && !budget.count(),"section allocation budget leaked state");
		const auto draw_icon = [&](uint64_t data, size_t size, const std::string &name, bool negatives) {
			const auto icon = api("CreateIconFromResourceEx",{data,size,1,0x30000,0,0,0});
			check(icon && objects.icon(icon),"draw source icon failed");
			const auto width = objects.icon(icon)->image.color.width, height = objects.icon(icon)->image.color.height;
			const auto dc = api("CreateCompatibleDC",{0});
			section_header(width,height);
			const auto bitmap = api("CreateDIBSection",{dc,buffer+2048,0,buffer+128,0,0});
			const auto pixels = number(process.read_memory(buffer+128,8),0);
			check(dc && bitmap && pixels && objects.bitmap(bitmap)->bits.empty(),"surface duplicated guest pixel ownership");
			const auto stock = api("SelectObject",{dc,bitmap});
			check(stock && !api("DeleteObject",{bitmap}),"selected bitmap was deleted");
			std::vector<uint8_t> background(size_t(width)*height*4);
			for (size_t byte = 0; byte < background.size(); byte+=4) {
				background[byte]=0x91; background[byte+1]=0x73; background[byte+2]=0x42;
			}
			if (negatives) {
				const auto other = api("CreateCompatibleDC",{dc});
				check(other && !api("SelectObject",{other,bitmap}) && api("DeleteObject",{other}),"bitmap was selected into two DCs");
				process.write_memory(pixels,background);
				check(!api("DrawIconEx",{bitmap,0,0,icon,0,0,0,0,3}) &&
					!api("DrawIconEx",{dc,0,0,bitmap,0,0,0,0,3}) &&
					!api("DrawIconEx",{dc,0,0,icon,0,0,0,1,3}) && environment.last_error()==120 &&
					process.read_memory(pixels,background.size())==background,"unsupported draw modified pixels");
				check(process.read_memory(pixels,background.size())==background,"failed drawing changed surface pixels");
			}
			// Another size stretches the icon into that rectangle and leaves the rest of the surface alone.
			process.write_memory(pixels,background);
			check(api("DrawIconEx",{dc,0,0,icon,0,0,0,0,3}),"icon drawing failed");
			const bool visible=process.read_memory(pixels,background.size())!=background;
			process.write_memory(pixels,background);
			check(api("DrawIconEx",{dc,0,0,icon,width/2,height/2,0,0,3}),"stretched icon drawing failed");
			{
				const auto bits=process.read_memory(pixels,background.size());
				bool inside=false,outside=false;
				for (uint32_t y=0; y<height; ++y)
					for (uint32_t x=0; x<width; ++x) {
						const size_t at=(size_t(y)*width+x)*4;
						if (!std::equal(bits.begin()+at,bits.begin()+at+4,background.begin()+at))
							(x<width/2 && y<height/2 ? inside : outside)=true;
					}
				check(inside || !visible,"stretched icon drew nothing");
				check(!outside,"stretched icon was drawn outside its rectangle");
			}
			std::filesystem::create_directories(evidence/"draw");
			for (unsigned mode=1; mode<=3; ++mode) {
				process.write_memory(pixels,background);
				check(api("DrawIconEx",{dc,0,0,icon,width,height,0,0,mode}),"native icon drawing failed");
				std::array<uint8_t,8> header{};
				for (size_t byte=0; byte<4; ++byte) {
					header[byte]=uint8_t(width>>(byte*8)); header[byte+4]=uint8_t(height>>(byte*8));
				}
				const auto bits=process.read_memory(pixels,background.size());
				std::ofstream file(evidence/"draw"/(name+"-"+std::to_string(mode)+".bgra"),std::ios::binary);
				file.write(reinterpret_cast<const char *>(header.data()),header.size());
				file.write(reinterpret_cast<const char *>(bits.data()),static_cast<std::streamsize>(bits.size()));
				check(bool(file),"native draw output could not be saved");
			}
			check(api("SelectObject",{dc,stock})==bitmap && api("DeleteObject",{bitmap}) && api("DeleteDC",{dc}) &&
				api("DestroyIcon",{icon}) && !objects.count() && !objects.bytes(),"surface/DC/icon ownership leaked");
			std::string stale;
			try { process.read_memory(pixels,1); } catch (const std::runtime_error &error) { stale=error.what(); }
			check(stale.find("readable")!=stale.npos,"deleted section remained mapped");
		};
		process.write_memory(buffer,color_icon);
		draw_icon(buffer,sizeof(color_icon),"known-32.dib",true);
		process.write_memory(buffer,mono_icon);
		draw_icon(buffer,sizeof(mono_icon),"known-mono",false);
		process.write_memory(buffer,black_palette_icon);
		draw_icon(buffer,sizeof(black_palette_icon),"known-black-palette",false);
		process.write_memory(buffer,png_icon);
		draw_icon(buffer,sizeof(png_icon),"known-png",false);
		for (const auto &resource : resources)
			if (resource.type==raven::ResourceKey(uint32_t(3)) && application.loaded.data()[resource.data_address]!=137)
				draw_icon(application.loaded.base()+resource.data_address,resource.size,std::to_string(std::get<uint32_t>(resource.name))+".dib",false);
		const auto save_icon = [&](const raven::PEResource &resource, uint32_t width, uint32_t height,
			const std::filesystem::path &path) {
			const auto handle = api("CreateIconFromResourceEx",{application.loaded.base()+resource.data_address,
				resource.size,1,0x30000,width,height,0});
			check(handle && api("GetIconInfo",{handle,buffer+512}),"resized real icon could not be queried");
			const auto info = process.read_memory(buffer+512,32);
			for (unsigned field : {16U,24U}) {
				const auto bitmap = number(info,field);
				if (!bitmap)
					continue;
				check(api("GetObjectW",{bitmap,32,output}) == 32,"resized bitmap metadata unavailable");
				auto bytes = process.read_memory(output,32);
				const auto size = objects.bitmap(bitmap)->bits.size();
				check(size <= 1024*1024 && api("GetBitmapBits",{bitmap,size,output}) == size,"resized bitmap pixels unavailable");
				const auto bits = process.read_memory(output,size);
				bytes.insert(bytes.end(),bits.begin(),bits.end());
				std::ofstream file(path.string()+(field==16?".mask":".color"),std::ios::binary);
				file.write(reinterpret_cast<const char *>(bytes.data()),static_cast<std::streamsize>(bytes.size()));
				check(bool(file) && api("DeleteObject",{bitmap}),"resized bitmap did not save or release");
			}
			check(api("DestroyIcon",{handle}) && !objects.count() && !objects.bytes(),"resized real icon leaked ownership");
		};
		const auto icon_resource = [&](uint32_t id) -> const raven::PEResource & {
			for (const auto &resource : resources)
				if (resource.type == raven::ResourceKey(uint32_t(3)) && resource.name == raven::ResourceKey(id))
					return resource;
			throw std::runtime_error("selected real image resource missing");
		};
		std::filesystem::create_directories(evidence/"resized/groups");
		std::filesystem::create_directories(evidence/"resized/dib");
		std::ofstream selections(evidence / "lookup.csv", std::ios::trunc);
		check(bool(selections), "cannot save guest selection evidence");
		for (const auto &resource : application.image.resources()) {
			if (resource.type != raven::ResourceKey(uint32_t(14)) || resource.name != raven::ResourceKey(uint32_t(100)))
				continue;
			const std::array<uint32_t,25> sizes{0,1,12,13,15,16,17,20,24,25,31,32,33,40,47,48,49,64,96,128,192,200,255,256,300};
			const auto record = [&](uint32_t width, uint32_t height) {
				environment.set_last_error(71);
				const auto id = api("LookupIconIdFromDirectoryEx", {application.loaded.base() + resource.data_address,1,width,height,0});
				check(id && environment.last_error() == 71 && !objects.count(), "guest lookup changed LastError or desktop ownership");
				selections << "100," << width << ',' << height << ",0," << id << '\n';
				save_icon(icon_resource(width||height?uint32_t(id):7),width,height,
					evidence/"resized/groups"/("100-"+std::to_string(width)+"-"+std::to_string(height)));
			};
			for (const auto size : sizes)
				record(size,size);
			for (uint32_t width = 16; width <= 48; width += 8)
				for (uint32_t height = 16; height <= 48; height += 8)
					if (width != height)
						record(width,height);
		}
		check(bool(selections), "guest selection evidence write failed");
		unsigned created = 0;
		for (const auto &resource : application.image.resources()) {
			if (resource.type != raven::ResourceKey(uint32_t(3)))
				continue;
			const auto handle = api("CreateIconFromResourceEx", {application.loaded.base() + resource.data_address,
				resource.size, 1, 0x30000, 0, 0, 0});
			check(handle && objects.icon(handle), "real application icon could not be created");
			check(api("GetIconInfo", {handle, buffer + 512}), "real icon did not publish bitmap copies");
			const auto info = process.read_memory(buffer + 512, 32);
			for (const auto field : {16U, 24U}) {
				const auto bitmap = number(info, field);
				if (!bitmap)
					continue;
				check(api("GetObjectW", {bitmap, 32, output}) == 32, "real bitmap metadata unavailable");
				auto bytes = process.read_memory(output, 32);
				const auto count = objects.bitmap(bitmap)->bits.size();
				check(count <= 1024 * 1024 && api("GetBitmapBits", {bitmap, count, output}) == count,
					"real bitmap pixels unavailable");
				const auto bits = process.read_memory(output, count);
				bytes.insert(bytes.end(), bits.begin(), bits.end());
				const auto id = std::get<uint32_t>(resource.name);
				std::ofstream file(evidence / (std::to_string(id) + (field == 16 ? ".mask" : ".color")), std::ios::binary | std::ios::trunc);
				file.write(reinterpret_cast<const char *>(bytes.data()), static_cast<std::streamsize>(bytes.size()));
				check(bool(file), "cannot save real guest bitmap evidence");
				check(api("DeleteObject", {bitmap}), "real bitmap copy did not release");
			}
			check(api("DestroyIcon", {handle}) && objects.count() == 0 && objects.bytes() == 0,
				"real icon leaked desktop storage");
			++created;
		}
		check(created == 2060, "real application icon corpus changed");
		unsigned scaled_dibs = 0;
		for (const auto &resource : resources) {
			if (resource.type != raven::ResourceKey(uint32_t(3)) || resource.size < 4)
				continue;
			const auto header = application.loaded.data().subspan(resource.data_address,4);
			if (header[0] != 40 || header[1] || header[2] || header[3])
				continue;
			for (uint32_t size : {13U,20U})
				save_icon(resource,size,size,evidence/"resized/dib"/(std::to_string(std::get<uint32_t>(resource.name))+"-"+
					std::to_string(size)+"-"+std::to_string(size)));
			++scaled_dibs;
		}
		check(scaled_dibs == 31,"real resized DIB corpus changed");
		process.unmap_image(application.loaded.base());
		modules.remove(application);
		std::cout << "SDK icon/bitmap lifetime and pixels, one typed owner, rollback and unsupported controls passed\n";
		return 0;
	} catch (const std::exception &error) {
		std::cerr << error.what() << '\n';
		return 1;
	}
}
