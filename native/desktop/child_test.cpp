#include "nt/providers.h"
#include "objects.h"

#include <algorithm>
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
		{
			raven::DesktopObjects objects;
			const auto atom=objects.register_class({"child owner",1,1});
			const auto root=objects.add(raven::DesktopWindow{atom,1,u"",100,200,80,60});
			raven::DesktopWindow first{atom,1,u"",105,206,20,15};first.parent=root;first.child_id=101;first.visible=true;
			const auto child=objects.add(first);
			raven::DesktopWindow second{atom,1,u"",102,210,8,7};second.parent=child;second.child_id=102;second.visible=true;
			const auto nested=objects.add(second);
			check(root && child && nested && objects.window_root(nested)==root && objects.is_child(root,nested) &&
				!objects.is_child(child,child) && !objects.is_child(nested,root) && !objects.window_visible(nested),"child owner ancestry differs");
			objects.window(root)->visible=true;
			check(objects.window_visible(nested) && objects.child_windows(root)==std::vector<uint64_t>{child} && !objects.erase(root) && !objects.erase(child),"child owner visibility or erase guard differs");
			const auto bitmap=objects.add(raven::DesktopBitmap{80,60,32,std::vector<uint8_t>(80*60*4)});
			raven::DesktopDC view{bitmap,bitmap,nested};view.leased=true;objects.configure_window_dc(nested,view,false);
			check(view.origin_x==2 && view.origin_y==10 && view.bounds && view.bounds->left==3 && view.bounds->right==8 &&
				view.bounds->top==0 && view.bounds->bottom==7 && !view.contains(4,10) && view.contains(5,10) && !view.contains(10,10),"nested DC escaped its parent clip");
			const auto dc=objects.add(view);
			objects.window(root)->visible=false;objects.update_window_dcs(root);
			check(!objects.dc(dc)->contains(5,10),"hidden ancestor retained a drawable child DC");
			objects.window(root)->visible=true;objects.update_window_dcs(root);
			check(objects.dc(dc)->contains(5,10),"showing the ancestor did not restore its held child DC");
			objects.detach_window_dcs(nested);
			check(!objects.dc(dc)->bitmap && !objects.dc(dc)->contains(5,10) && objects.bitmap(bitmap),"child DC detachment damaged root storage");
			check(objects.erase(nested) && objects.erase(child) && objects.erase(root) && objects.erase(dc) && objects.erase(bitmap) &&
				!objects.unregister_class(atom) && !objects.count() && !objects.bytes(),"child owner leaked objects");
		}
		check(argc>=3 && argc<=5,"bootstrap, child fixture, optional input mode and output prefix required");
		const bool input=argc>=4 && std::string_view(argv[3])=="--input";
		const bool reject=argc>=4 && std::string_view(argv[3])=="--reject";
		const char *prefix=input || reject ? (argc==5 ? argv[4] : nullptr) : (argc==4 ? argv[3] : nullptr);
		std::ifstream file(argv[2],std::ios::binary|std::ios::ate);
		check(bool(file) && file.tellg()>0,"cannot read child fixture");
		std::vector<uint8_t> bytes(size_t(file.tellg()));file.seekg(0);
		check(bool(file.read(reinterpret_cast<char *>(bytes.data()),std::streamsize(bytes.size()))),"short child fixture");
		raven::ModuleSet modules;auto &entry=modules.add("child.exe",bytes);
		uint64_t root=0;unsigned frames=0,removed=0;std::vector<uint8_t> last;
		raven::DesktopPresentation presentation;
		presentation.present=[&](uint64_t handle,std::string_view title,uint32_t width,uint32_t height,std::span<const uint8_t> pixels) {
			check(handle && (!root || root==handle) && title=="child surface" && width==80 && height==60 && pixels.size()==80*60*4,"child created a second host surface");
			root=handle;++frames;last.assign(pixels.begin(),pixels.end());
		};
		uint64_t dropped=0;int32_t dropped_x=-1,dropped_y=-1;
		presentation.owned_popup=[&](uint64_t handle,uint64_t owner,int32_t x,int32_t y,uint32_t,uint32_t,std::span<const uint8_t>) {
			check(root && owner==root,"a child moved to the desktop showed on another host window");
			dropped=handle;dropped_x=x;dropped_y=y;
		};
		presentation.remove=[&](uint64_t handle) {
			if (dropped && handle==dropped) return;
			if (reject && !root) root=handle;check(root && handle==root,"child removed its parent's presentation");++removed;
		};
		bool injected=false;
		if (input) presentation.poll=[&](std::chrono::milliseconds) {
			std::vector<raven::DesktopEvent> events;
			if (root && frames>=1 && !injected) {
				injected=true;
				for(unsigned i=0;i<6;++i) events.push_back({root,0x110,i & 1 ? 0ULL : 1ULL,0,raven::DesktopEventKind::pointer_button,i<2 ? 6 : 20,i<2 ? 11 : 8});
			}
			return events;
		};
		const auto result=raven::run_native_process(modules,entry,argv[1],std::chrono::seconds(10),{},{},presentation);
		if (reject) {
			if (prefix) {
				const auto symbol=std::find_if(entry.exports.begin(),entry.exports.end(),[](const auto &item) {
					return std::find(item.names.begin(),item.names.end(),"reject_rows")!=item.names.end();
				});check(symbol!=entry.exports.end(),"rejection rows missing");
				const auto data=entry.loaded.data().subspan(symbol->address,64*32);
				std::ofstream output(std::string(prefix)+".reject-rows",std::ios::binary);
				output.write(reinterpret_cast<const char *>(data.data()),std::streamsize(data.size()));check(bool(output),"cannot save rejection rows");
			}
			if (result.stop!=raven::NativeStop::returned || result.value) std::cerr<<"child rejection stop="<<int(result.stop)<<" value="<<result.value<<'\n';
			check(result.stop==raven::NativeStop::returned && !result.value,"rejected creation SDK contract differs");
			check(!frames && removed==1,"rejected parent did not release its one root surface");return 0;
		}
		if (result.stop!=raven::NativeStop::returned || result.value) {
			std::cerr<<"child SDK stop="<<int(result.stop)<<" value="<<result.value<<'\n';return 1;
		}
		check(frames && removed==1 && (!input || injected),"child presentation lifecycle differs");
		check(!input || (dropped && dropped_x==30 && dropped_y==30),"a child moved to the desktop did not show where the program placed it");
		const auto pixel_export=std::find_if(entry.exports.begin(),entry.exports.end(),[](const auto &symbol) {
			return std::find(symbol.names.begin(),symbol.names.end(),"child_pixels")!=symbol.names.end();
		});check(pixel_export!=entry.exports.end(),"child pixels export missing");
		const auto pixels=entry.loaded.data().subspan(pixel_export->address,last.size());
		check(std::equal(last.begin(),last.end(),pixels.begin()),"child drawing differs between root DC and presentation");

		if (prefix) {
			const auto save=[&](std::string_view name,size_t size,const char *suffix) {
				const auto symbol=std::find_if(entry.exports.begin(),entry.exports.end(),[&](const auto &item) {
					return std::find(item.names.begin(),item.names.end(),name)!=item.names.end();
				});check(symbol!=entry.exports.end(),"child evidence export missing");
				const auto data=entry.loaded.data().subspan(symbol->address,size);
				std::ofstream output(std::string(prefix)+suffix,std::ios::binary);
				output.write(reinterpret_cast<const char *>(data.data()),std::streamsize(data.size()));check(bool(output),"cannot save child evidence");
			};
			save("child_input",6*6*8,".input");save("child_pixels",80*60*4,".pixels");save("child_rows",128*32,".rows");
			std::ofstream output(std::string(prefix)+".presentation",std::ios::binary);
			output.write(reinterpret_cast<const char *>(last.data()),std::streamsize(last.size()));check(bool(output),"cannot save child presentation");
		}
	} catch (const std::exception &error) { std::cerr<<error.what()<<'\n';return 1; }
	return 0;
}
