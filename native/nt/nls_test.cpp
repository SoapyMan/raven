#include "nls.h"

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
		check(argc==2,"CP1252 NT reference file required");
		std::ifstream file(argv[1],std::ios::binary);
		std::string expected(65536,'\0');
		check(bool(file.read(expected.data(),std::streamsize(expected.size()))) && file.get()==EOF,"invalid CP1252 reference size");
		std::u16string text;
		for (uint32_t value=0;value<65536;++value) text.push_back(char16_t(value));
		check(raven::encode_ansi(text,1252)==expected,"native CP1252 differs from the full NT reference");
		check(raven::encode_ansi(u"",1252).empty() && raven::encode_ansi(u"ASCII",1252)=="ASCII","empty or ASCII conversion differs");
		check(raven::encode_ansi(u"\u00e9\u4e2d\U0001f642",1252)==std::string("\xe9???",4),"best-fit/default/surrogate conversion differs");
		// Each other Windows single-byte page reads every byte back as itself, and best-fits only where an exact byte is missing.
		for (const uint32_t code_page : {1250U,1251U,1253U,1254U,1255U,1256U,1257U,1258U}) {
			const auto *page=raven::native_single_byte_page(code_page);
			check(page && page->best_fit_count>=256,"single-byte code page missing");
			for (unsigned byte=0;byte<256;++byte)
				check(raven::encode_single_byte(*page,char16_t(page->bytes[byte]),true)==int(byte),"single-byte page does not round-trip");
			for (size_t at=1;at<page->best_fit_count;++at) check(page->best_fit[at-1][0]<page->best_fit[at][0],"best-fit table out of order");
		}
		const auto *central=raven::native_single_byte_page(1250),*cyrillic=raven::native_single_byte_page(1251);
		check(raven::decode_single_byte(*central,"\x8a\xc3")==u"\u0160\u0102" && raven::decode_single_byte(*cyrillic,"\xc0")==u"\u0410",
			"single-byte decoding differs from the code page table");
		check(raven::encode_ansi(u"\u00e9\u0410\u4e2d",1251)=="e\xc0?" && raven::encode_single_byte(*cyrillic,u'\u00e9',true)<0,
			"single-byte best fit differs from the code page table");
		for (const uint32_t code_page : {0U,874U,932U,65001U}) {
			bool rejected=false;
			try { raven::encode_ansi(u"",code_page); } catch (const std::runtime_error &) { rejected=true; }
			check(rejected,"unsupported code page produced apparent success");
		}
		std::cout<<"All 65536 native CP1252 code units match NT; the other single-byte pages round-trip; unsupported code pages reject explicitly\n";
	} catch (const std::exception &error) { std::cerr<<error.what()<<'\n'; return 1; }
	return 0;
}
