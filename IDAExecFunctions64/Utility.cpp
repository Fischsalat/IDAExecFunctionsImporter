#include "Utility.hpp"

#include <algorithm>
#include <string_view>

#ifdef __NT__
#include <Windows.h>
#else
#include <dlfcn.h>
#include <link.h>
#endif

#include <ida.hpp>
#include <segment.hpp>
#include <bytes.hpp>


std::string WStrToStr(const std::wstring& WStr)
{
	std::string Str;
	Str.reserve(WStr.size());

	for (size_t Index = 0; Index < WStr.size(); ++Index)
	{
		uint32 CodePoint = static_cast<uint32>(WStr[Index]);

		if (CodePoint >= 0xD800 && CodePoint <= 0xDBFF && (Index + 1) < WStr.size())
		{
			const uint32 LowSurrogate = static_cast<uint32>(WStr[Index + 1]);
			if (LowSurrogate >= 0xDC00 && LowSurrogate <= 0xDFFF)
			{
				CodePoint = 0x10000 + ((CodePoint - 0xD800) << 10) + (LowSurrogate - 0xDC00);
				++Index;
			}
		}

		if (CodePoint < 0x80)
		{
			Str.push_back(static_cast<char>(CodePoint));
		}
		else if (CodePoint < 0x800)
		{
			Str.push_back(static_cast<char>(0xC0 | (CodePoint >> 6)));
			Str.push_back(static_cast<char>(0x80 | (CodePoint & 0x3F)));
		}
		else if (CodePoint < 0x10000)
		{
			Str.push_back(static_cast<char>(0xE0 | (CodePoint >> 12)));
			Str.push_back(static_cast<char>(0x80 | ((CodePoint >> 6) & 0x3F)));
			Str.push_back(static_cast<char>(0x80 | (CodePoint & 0x3F)));
		}
		else
		{
			Str.push_back(static_cast<char>(0xF0 | (CodePoint >> 18)));
			Str.push_back(static_cast<char>(0x80 | ((CodePoint >> 12) & 0x3F)));
			Str.push_back(static_cast<char>(0x80 | ((CodePoint >> 6) & 0x3F)));
			Str.push_back(static_cast<char>(0x80 | (CodePoint & 0x3F)));
		}
	}

	return Str;
}


std::vector<ea_t> FindWideStringLiteralsByContent(const char* Str)
{
	std::vector<ea_t> Ret;

	if (!Str || Str[0] == '\0')
		return Ret;

	auto AddUniqueAddress = [&Ret](const ea_t Address)
	{
		if (Address != BADADDR && std::find(Ret.begin(), Ret.end(), Address) == Ret.end())
			Ret.push_back(Address);
	};

	std::vector<uchar> Pattern;
	for (const char* Ch = Str; *Ch; ++Ch)
	{
		Pattern.push_back(static_cast<uchar>(*Ch));
		Pattern.push_back(0);
	}
	Pattern.push_back(0);
	Pattern.push_back(0);

	for (int SegIdx = 0; SegIdx < get_segm_qty(); ++SegIdx)
	{
		segment_t* Seg = getnseg(SegIdx);
		if (!Seg || !(Seg->perm & SEGPERM_READ) || (Seg->perm & SEGPERM_EXEC))
			continue;

		ea_t SearchStart = Seg->start_ea;
		while (SearchStart < Seg->end_ea)
		{
			const ea_t Found = bin_search(
				SearchStart,
				Seg->end_ea,
				Pattern.data(),
				nullptr,
				Pattern.size(),
				BIN_SEARCH_FORWARD
			);

			if (Found == BADADDR)
				break;

			AddUniqueAddress(Found);
			SearchStart = Found + 1;
		}
	}

	return Ret;
}

bool IsValidCodePointer(ea_t Address)
{
	segment_t* Seg = getseg(Address);
	if (!Seg)
		return false;

	return Seg->type == SEG_CODE;
}

#ifndef __NT__
namespace
{
	struct LoadedModuleSearch
	{
		std::string_view FileName;
		std::string Path;
	};

	int MatchLoadedModuleFileName(dl_phdr_info* Info, size_t, void* Context)
	{
		if (!Info->dlpi_name || Info->dlpi_name[0] == '\0')
			return 0;

		LoadedModuleSearch& Search = *static_cast<LoadedModuleSearch*>(Context);

		const std::string_view Path(Info->dlpi_name);
		const size_t FileNameStart = Path.find_last_of('/');

		if (Path.substr(FileNameStart == std::string_view::npos ? 0 : FileNameStart + 1) != Search.FileName)
			return 0;

		Search.Path = Path;
		return 1;
	}
}
#endif

void* FindLoadedPluginExport(const char* PluginName, const char* SymbolName)
{
#ifdef __NT__
	const HMODULE Module = GetModuleHandleA((std::string(PluginName) + ".dll").c_str());

	return Module ? reinterpret_cast<void*>(GetProcAddress(Module, SymbolName)) : nullptr;
#else
	const std::string FileName = std::string(PluginName) + ".so";

	LoadedModuleSearch Search{ FileName, {} };
	if (dl_iterate_phdr(&MatchLoadedModuleFileName, &Search) == 0)
		return nullptr;

	void* Module = dlopen(Search.Path.c_str(), RTLD_NOLOAD | RTLD_NOW);
	if (!Module)
		return nullptr;

	void* const Symbol = dlsym(Module, SymbolName);
	dlclose(Module);

	return Symbol;
#endif
}
