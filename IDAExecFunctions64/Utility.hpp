#pragma once
#include <string>
#include <vector>

#define __EA64__
#include <pro.h>

std::string WStrToStr(const std::wstring& WStr);
std::vector<ea_t> FindWideStringLiteralsByContent(const char* Str);

bool IsValidCodePointer(ea_t Address);

void* FindLoadedPluginExport(const char* PluginName, const char* SymbolName);
