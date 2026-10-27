#include "providers.h"
#include "environment.h"

#include <algorithm>
#include <fstream>
#include <iostream>
#include <iomanip>
#include <stdexcept>
#include <sys/mman.h>

static void check(bool value,const char *message)
{
	if (!value) throw std::runtime_error(message);
}

int main(int argc,char **argv)
{
	try {
		check(argc==3 || argc==4,"bootstrap, conversion fixture and optional rows file required");
		std::ifstream file(argv[2],std::ios::binary|std::ios::ate);
		check(bool(file) && file.tellg()>0,"cannot read conversion fixture");
		std::vector<uint8_t> bytes(size_t(file.tellg()));file.seekg(0);
		check(bool(file.read(reinterpret_cast<char *>(bytes.data()),std::streamsize(bytes.size()))),"short conversion fixture");
		raven::ModuleSet modules;auto &entry=modules.add("client.exe",bytes);
		const auto run=raven::run_native_process(modules,entry,argv[1],std::chrono::seconds(20));
		if (argc==4) {
			const auto found=std::find_if(entry.exports.begin(),entry.exports.end(),[](const auto &symbol) {
				return std::find(symbol.names.begin(),symbol.names.end(),"conversion_rows")!=symbol.names.end();
			});
			check(found!=entry.exports.end(),"conversion rows export missing");
			std::ofstream output(argv[3]);const auto rows=entry.loaded.data().subspan(found->address,900*24);
			for (unsigned i=0;i<900;++i) {
				uint64_t fields[3]={};for(unsigned j=0;j<3;++j)for(unsigned k=0;k<8;++k)fields[j]|=uint64_t(rows[i*24+j*8+k])<<(k*8);
				if (!fields[2]) break;
				output<<"row="<<std::dec<<i<<" result="<<fields[0]<<" error="<<fields[1]<<" digest="<<std::hex<<std::setfill('0')<<std::setw(16)<<fields[2]<<'\n';
			}
			check(bool(output),"cannot write conversion rows");
		}
		check(run.stop==raven::NativeStop::returned && !run.value,"SDK conversion digest differs");
		auto &kernel=*modules.all().at("kernel32.dll");
		raven::LoadedImage *images[]={&entry.loaded,&kernel.loaded};
		raven::NativeProcess process(images,argv[1],std::chrono::seconds(5));
		// The runtime's own conversion is under test: the call goes to the breakpoint behind the guest-side prelude of plain text.
		const auto exported=std::find_if(kernel.exports.begin(),kernel.exports.end(),[](const auto &symbol) {
			return std::find(symbol.names.begin(),symbol.names.end(),"MultiByteToWideChar")!=symbol.names.end();
		});
		check(exported!=kernel.exports.end(),"conversion export missing");
		const auto function=raven::api_trap_address(kernel,"kernel32.dll","MultiByteToWideChar",exported->address);process.add_api_trap(function);
		raven::NativeEnvironment environment(process,entry.loaded.base(),1,1);
		raven::NativeLaunch launch;launch.image_path=u"client.exe";launch.command_line=u"client.exe";environment.prepare_parameters(launch);
		const auto page=process.map_memory(8192,PROT_READ|PROT_WRITE);process.protect_memory(page+4096,4096,PROT_NONE);
		const std::array<uint8_t,3> input{'a','b',0};process.write_memory(page+4093,input);
		const auto output=process.map_memory(4096,PROT_READ|PROT_WRITE);
		const auto call=[&](std::initializer_list<uint64_t> args,std::optional<uint64_t> fault_access={}) {
			check(process.call(function,std::span(args.begin(),args.size()),std::chrono::seconds(1)).stop==raven::NativeStop::api,"conversion API did not trap");
			bool faulted=false;
			try { check(environment.dispatch("MultiByteToWideChar"),"conversion API not dispatched"); }
			catch (const raven::NativeResult &fault) {
				check(fault_access && fault.stop==raven::NativeStop::exception && fault.value==0xc0000005U &&
					fault.exception_information.size()==2 && fault.exception_information[0]==*fault_access,"conversion fault has wrong access record");
				faulted=true;process.return_api(0);
			}
			check(faulted==fault_access.has_value(),"conversion fault expectation differs");
			const auto result=process.resume(std::chrono::seconds(1));check(result.stop==raven::NativeStop::returned,"conversion API did not return");return result.value;
		};
		check(call({0,0,page+4093,UINT32_MAX,output,INT32_MAX})==3 &&
			process.read_memory(output,6)==std::vector<uint8_t>({'a',0,'b',0,0,0}),"terminated page-boundary conversion or large capacity failed");
		check(call({1252,0,page+4093,3,0x400000000000ULL,0})==3,"query accessed its ignored output pointer");
		call({1252,0,page+4093,4,output,8},0);
		call({1252,0,0x400000000000ULL,1,output,8},0);
		// The other single-byte pages read their bytes through their own tables.
		const std::array<uint8_t,2> regional{0x8a,0xc0};process.write_memory(output+256,regional);
		check(call({1250,0,output+256,2,output+512,8})==2 && process.read_memory(output+512,4)==std::vector<uint8_t>({0x60,1,0x54,1}) &&
			call({1251,0,output+256,2,output+512,8})==2 && process.read_memory(output+512,4)==std::vector<uint8_t>({0x09,4,0x10,4}),
			"single-byte code page conversion differs from its table");
		process.protect_memory(output,4096,PROT_READ);
		call({1252,0,page+4093,3,output,8},1);
		check(process.read_memory(output,6)==std::vector<uint8_t>({'a',0,'b',0,0,0}),"readonly output was modified");
	} catch (const std::exception &error) { std::cerr<<error.what()<<'\n';return 1; }
	return 0;
}
