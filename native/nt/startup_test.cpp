#include "providers.h"
#include "nls.h"
#include <filesystem>
#include <fstream>
#include <iostream>
#include <stdexcept>
#include <sys/mman.h>

static void check(bool value,const char *message)
{
	if (!value) throw std::runtime_error(message);
}
static std::vector<uint8_t> read_file(const std::filesystem::path &path)
{
	std::ifstream file(path,std::ios::binary | std::ios::ate);
	check(bool(file) && file.tellg()>0 && file.tellg()<1024*1024,"invalid startup fixture");
	std::vector<uint8_t> bytes(size_t(file.tellg()));file.seekg(0);
	check(bool(file.read(reinterpret_cast<char *>(bytes.data()),std::streamsize(bytes.size()))),"short startup fixture");return bytes;
}
static uint64_t number(std::span<const uint8_t> bytes,size_t offset,size_t length)
{
	uint64_t result=0;for(size_t i=0;i<length;++i) result|=uint64_t(bytes[offset+i])<<(i*8);return result;
}
int main(int argc,char **argv)
{
	try {
		check(argc==3,"bootstrap and startup executable required");
		raven::ModuleSet modules;auto &entry=modules.add("client.exe",read_file(argv[2]));
		for(const bool configured : {false,true}) {
			raven::NativeLaunch launch{u"client.exe",u"\"client.exe\""};
			if(configured) {
				launch.startup.title=u"title-\u00e9\u4e2d";launch.startup.geometry={11,22,33,44,55,66,77};
				launch.startup.flags=0x11f;launch.startup.show_window=9;launch.startup.runtime_data={0xaa,0,0xbb,0xcc,0xdd};
			}
			const auto result=raven::run_native_process(modules,entry,argv[1],std::chrono::seconds(5),{},{},{},launch);
			check(result.stop==raven::NativeStop::returned && !result.value,"compiled startup snapshot/live-field contract failed");
			const auto data=[&](const char *name,size_t length) {
				const auto offset=modules.resolve({"client.exe",name,0,false,0})-entry.loaded.base();
				return entry.loaded.data().subspan(size_t(offset),length);
			};
			const auto a=data("startup_a_before",104),w=data("startup_w_before",104);
			for(size_t i=0;i<7;++i) check(number(a,32+i*4,4)==launch.startup.geometry[i],"ANSI startup geometry differs");
			check(number(a,60,4)==launch.startup.flags && number(a,64,2)==launch.startup.show_window &&
				number(a,66,2)==launch.startup.runtime_data.size(),"ANSI flags/show/runtime count differs");
			for(size_t i=0;i<3;++i) check(number(a,80+i*8,8)==UINT64_MAX && number(w,80+i*8,8)==UINT64_MAX,"metadata invented standard handles");
			uint64_t digest=14695981039346656037ULL;
			for(const char byte : raven::encode_ansi(launch.startup.title ? *launch.startup.title : launch.image_path,1252))
				digest=(digest^static_cast<unsigned char>(byte))*1099511628211ULL;
			check(number(data("startup_title_digest",8),0,8)==digest,"ANSI startup title lost its initial data");
		}
		std::vector<raven::LoadedImage *> images;for(const auto &[name,module] : modules.all()) images.push_back(&module->loaded);
		raven::NativeProcess process(images,argv[1],std::chrono::seconds(5));
		raven::NativeEnvironment environment(process,entry.loaded.base(),1,1);
		environment.prepare_parameters({u"client.exe",u"command"});
		const auto proxy=modules.resolve({"kernel32.dll","GetStartupInfoW",0,false,0});
		const auto &kernel=*modules.all().at("kernel32.dll");
		process.add_api_trap(raven::api_trap_address(kernel,"kernel32.dll","GetStartupInfoW",uint32_t(proxy-kernel.loaded.base())));
		const auto invoke=[&](const char *name,uint64_t output) {
			const uint64_t args[]={output};check(process.call(proxy,args,std::chrono::seconds(2)).stop==raven::NativeStop::api,"startup proxy did not stop");
			check(environment.dispatch(name),"startup handler did not dispatch");return process.resume(std::chrono::seconds(2));
		};
		const auto page=process.map_memory(8192,PROT_READ | PROT_WRITE);
		process.protect_memory(page+4096,4096,PROT_NONE);
		process.write_memory(page,std::vector<uint8_t>(4096,0x5a));environment.set_last_error(91);
		check(invoke("GetStartupInfoW",page+4096-80).stop==raven::NativeStop::returned && environment.last_error()==91,
			"wide startup accessed unused standard handles across the mapping boundary");
		const auto prefix=process.read_memory(page+4096-80,80);check(prefix[4]==0x5a && prefix[68]==0x5a,"wide padding changed");
		process.protect_memory(page,4096,PROT_READ);
		const uint64_t args[]={page};check(process.call(proxy,args,std::chrono::seconds(2)).stop==raven::NativeStop::api,"readonly startup did not stop");
		bool faulted=false;
		try { environment.dispatch("GetStartupInfoW"); } catch(const raven::NativeResult &fault) {
			faulted=fault.stop==raven::NativeStop::exception && fault.value==0xc0000005U && fault.fault_address==page &&
				fault.exception_information==std::vector<uint64_t>{1,page};
		}
		check(faulted && process.read_memory(page+4096-80,80)==prefix && environment.last_error()==91,"readonly startup did not preserve output or report its write fault");
		process.return_api(0);process.resume(std::chrono::seconds(2));
		process.unmap_memory(page);
		std::cout<<"Native startup A snapshot, W live fields, padding, binary pointer and buffer bounds passed\n";
	} catch(const std::exception &error) { std::cerr<<error.what()<<'\n';return 1; }
	return 0;
}
