#include "nt/providers.h"
#include <xkbcommon/xkbcommon.h>
#include <cstdlib>
#include <fstream>
#include <iostream>
#include <stdexcept>

static void check(bool value,const char *message)
{
	if (!value) throw std::runtime_error(message);
}

int main(int argc,char **argv)
{
	try {
		check(argc==3 || argc==4,"bootstrap, keyboard fixture and optional focus case required");
		const std::string mode=argc==4 ? argv[3] : "normal";
		std::ifstream file(argv[2],std::ios::binary | std::ios::ate); check(bool(file) && file.tellg()>0,"cannot read keyboard fixture");
		std::vector<uint8_t> bytes(size_t(file.tellg())); file.seekg(0);
		check(bool(file.read(reinterpret_cast<char *>(bytes.data()),std::streamsize(bytes.size()))),"short keyboard fixture");
		auto *context=xkb_context_new(XKB_CONTEXT_NO_FLAGS); check(context,"cannot create reference keyboard context");
		xkb_rule_names names{}; names.layout="us";
		const auto serialize=[&] {
			auto *map=xkb_keymap_new_from_names(context,&names,XKB_KEYMAP_COMPILE_NO_FLAGS); check(map,"cannot create reference keyboard map");
			auto *text=xkb_keymap_get_as_string(map,XKB_KEYMAP_FORMAT_TEXT_V1); check(text,"cannot serialize keyboard map");
			const std::string serialized(text); std::free(text); xkb_keymap_unref(map); return serialized;
		};
		const std::string keymap=serialize();
		// The same keys under another layout: the held g key becomes i, and its release still has to end the g press.
		names.variant="dvorak";
		const std::string remapped=serialize(); xkb_context_unref(context);
		raven::ModuleSet modules; auto &entry=modules.add("keyboard.exe",bytes);
		unsigned frames=0,removed=0;
		uint64_t window=0;
		bool typed=false,closed=false;
		raven::DesktopPresentation presentation;
		presentation.present=[&](uint64_t handle,std::string_view title,uint32_t width,uint32_t height,std::span<const uint8_t> pixels) {
			check(handle && (!window || window==handle) && width==32 && height==32 && pixels.size()==4096,"keyboard surface identity differs"); window=handle;
			check(title==(frames<2 ? "Raven native paint" : "Keyboard: g"),"guest character did not update the caption");
			if (frames) for (unsigned y=0;y<32;++y) for (unsigned x=0;x<32;++x) {
				const auto at=(y*32+x)*4;
				check(pixels[at]==x*7 && pixels[at+1]==(31-y)*7 && pixels[at+2]==192,"keyboard workflow damaged pixels");
			}
			++frames;
		};
		presentation.remove=[&](uint64_t handle) { check(handle==window,"removed wrong keyboard surface"); ++removed; };
		presentation.poll=[&](std::chrono::milliseconds) {
			std::vector<raven::DesktopEvent> events;
			if (frames==2 && !typed) {
				typed=true; raven::DesktopEvent layout{0,0}; layout.kind=raven::DesktopEventKind::keymap; layout.keymap=keymap;
				events.push_back(std::move(layout));
				raven::DesktopEvent focused{window,0,0,0,raven::DesktopEventKind::keyboard_focus};
				if (mode!="normal" && mode!="remap") focused.held_keys={34,125};
				if (mode=="duplicate") focused.held_keys={34,34};
				if (mode=="outofrange") focused.held_keys={256};
				if (mode=="nofocus") focused.window=0;
				events.push_back(std::move(focused));
				if (mode=="held") {
					events.push_back({window,34,0,0,raven::DesktopEventKind::key});
					events.push_back({window,125,1,0,raven::DesktopEventKind::key});
					events.push_back({window,125,0,0,raven::DesktopEventKind::key});
				}
				events.push_back({window,34,1,0,raven::DesktopEventKind::key});
				if (mode=="remap") {
					raven::DesktopEvent change{0,0}; change.kind=raven::DesktopEventKind::keymap; change.keymap=remapped;
					events.push_back(std::move(change));
				}
				events.push_back({window,34,0,0,raven::DesktopEventKind::key});
			} else if (frames==3 && !closed) { closed=true; events.push_back({window,0x10}); }
			return events;
		};
		if (mode!="normal" && mode!="held" && mode!="remap") {
			bool rejected=false;
			try { raven::run_native_process(modules,entry,argv[1],std::chrono::seconds(5),{},{},presentation); }
			catch (const std::runtime_error &error) {
				const std::string expected=mode=="nofocus" ? "keyboard focus requires its visible guest window" : "invalid initial keyboard key state";
				check(error.what()==expected,"initial keyboard state failed for an unexpected reason"); rejected=true;
			}
			check(rejected,"invalid initial keyboard state succeeded");
		} else {
			const auto result=raven::run_native_process(modules,entry,argv[1],std::chrono::seconds(5),{},{},presentation);
			check(result.stop==raven::NativeStop::returned && !result.value && typed && closed && frames==3 && removed==1,"SDK keyboard workflow failed");
		}
	} catch (const std::exception &error) { std::cerr<<error.what()<<'\n'; return 1; }
	return 0;
}
