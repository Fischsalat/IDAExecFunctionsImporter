
#include "StaticClassNamer.hpp"

#include <unordered_map>
#include <string>
#include <utility>
#include <unordered_set>
#include <cstdint>

#include <ida.hpp>
#include <funcs.hpp>
#include <name.hpp>
#include <typeinf.hpp>
#include <allins.hpp>

#include <Windows.h>

#include "Utility.hpp"

#include <string_view>
#include <Format/Parser.hpp>

/*
 * Note: The content of both StaticClassNamer.hpp and StaticClassNamer.cpp is AI generated
 */


std::unordered_map<std::string, std::pair<char, uint8_t>> PrefixCache;

constexpr asize_t MinNonInlinedStaticClassSize = 0x80;
constexpr asize_t MaxNonInlinedStaticClassSize = 0x100;


bool IsLikelyNonInlinedStaticClass(const func_t* Function)
{
	if (!Function)
		return false;

	const asize_t FunctionSize = Function->end_ea - Function->start_ea;
	return FunctionSize >= MinNonInlinedStaticClassSize && FunctionSize <= MaxNonInlinedStaticClassSize;
}


std::unordered_set<func_t*> GetFunctionsReferencingThisFunction(const ea_t Address)
{
	std::unordered_set<func_t*> Ret;

	xrefblk_t Xref;
	for (bool Ok = Xref.first_to(Address, XREF_ALL); Ok; Ok = Xref.next_to())
	{
		if (func_t* Function = get_func(Xref.from))
			Ret.insert(Function);
	}

	return Ret;
}

std::unordered_set<func_t*> GetFunctionsReferencingAnyAddress(const std::vector<ea_t>& Addresses)
{
	std::unordered_set<func_t*> Ret;

	for (const ea_t Address : Addresses)
	{
		if (Address == BADADDR)
			continue;

		std::unordered_set<func_t*> Refs = GetFunctionsReferencingThisFunction(Address);
		Ret.insert(Refs.begin(), Refs.end());
	}

	return Ret;
}

// Collect all call targets inside a function's body, in address order.
static std::vector<ea_t> GetCallTargetsInFunc(func_t* Func)
{
	std::vector<ea_t> CallTargets;

	for (ea_t Addr = Func->start_ea; Addr < Func->end_ea; Addr = next_head(Addr, Func->end_ea))
	{
		if (!is_code(get_flags(Addr)))
			continue;

		insn_t Insn;
		if (decode_insn(&Insn, Addr) <= 0)
			continue;

		if (!is_call_insn(Insn))
			continue;

		const op_t& Op = Insn.ops[0];
		if (Op.type == o_near || Op.type == o_far)
			CallTargets.push_back(Op.addr);
		else if (Op.type == o_mem || Op.type == o_displ)
			CallTargets.push_back(Op.addr); // indirect — still record it
	}

	return CallTargets;
}

bool IsUnrealScriptPackagePath(const std::wstring& WStr)
{
	return WStr.starts_with(L"/Script/");
}

static std::wstring ReadAsciiWideStringAt(ea_t Addr)
{
	if (Addr == BADADDR)
		return {};

	const uint16 FirstWord = get_word(Addr);
	if (FirstWord < 0x20 || FirstWord > 0x7E)
		return {};

	std::wstring Str;
	for (int CharIdx = 0; CharIdx < 512; ++CharIdx)
	{
		const uint16 Ch = get_word(Addr + CharIdx * 2);
		if (Ch == 0)
			break;
		if (Ch > 0x7E) // non-ASCII -> not the string we want
			return {};
		Str.push_back(static_cast<wchar_t>(Ch));
	}

	return Str;
}

static std::string GetStaticClassNameFromBodyCall(func_t* Func, ea_t BodyAddr)
{
	constexpr int RegRcx = 1;     // arg 1
	constexpr int RegRdx = 2;     // arg 2
	constexpr int NumGpRegs = 16; // rax..r15

	ea_t RegTarget[NumGpRegs];
	for (int i = 0; i < NumGpRegs; ++i)
		RegTarget[i] = BADADDR;

	for (ea_t Addr = Func->start_ea; Addr < Func->end_ea; Addr = next_head(Addr, Func->end_ea))
	{
		if (!is_code(get_flags(Addr)))
			continue;

		insn_t Insn;
		if (decode_insn(&Insn, Addr) <= 0)
			continue;

		// Track string pointers loaded into registers (directly, or copied between regs)
		if (Insn.ops[0].type == o_reg && Insn.ops[0].reg < NumGpRegs)
		{
			if (Insn.itype == NN_lea)
				RegTarget[Insn.ops[0].reg] = Insn.ops[1].addr;
			else if (Insn.itype == NN_mov && Insn.ops[1].type == o_reg && Insn.ops[1].reg < NumGpRegs)
				RegTarget[Insn.ops[0].reg] = RegTarget[Insn.ops[1].reg];
		}

		if (is_call_insn(Insn) && Insn.ops[0].type == o_near && Insn.ops[0].addr == BodyAddr)
		{
			const std::wstring Package = ReadAsciiWideStringAt(RegTarget[RegRcx]);
			const std::wstring Name = ReadAsciiWideStringAt(RegTarget[RegRdx]);

			// arg1 should be a "/Script/..." package path and arg2 is the class name
			if (!Name.empty() && (Package.empty() || IsUnrealScriptPackagePath(Package)))
				return WStrToStr(Name);

			for (int i = 0; i < NumGpRegs; ++i)
				RegTarget[i] = BADADDR;
		}
	}

	return {};
}

std::string GetPrefixedName(const std::string& ObjectName)
{
	auto It = PrefixCache.find(ObjectName);
	if (It != PrefixCache.end())
	{
		auto& [Prefix, AccessCounter] = It->second;
		return Prefix + ObjectName + (AccessCounter++ > 0 ? std::to_string(AccessCounter) : "");
	}

	return ObjectName;
}

void ClearStaticClassPrefixCache()
{
	PrefixCache.clear();
}

void BuildStaticClassPrefixCache(MappingParser& Parser)
{
	// .idmap struct names are C++-prefixed (ACharacter, UObject, ...). The raw name a
	// StaticClass() call passes is the rest, and the leading char is the prefix. Only
	// A/U types are UClasses with a StaticClass(), so skip everything else.
	for (const IDAMappingsLayouts::Struct* StructInfo : Parser.GetAllStructs())
	{
		const std::string_view PrefixedName = Parser.GetNameFromOffset(StructInfo->Name);
		if (PrefixedName.size() < 2)
			continue;

		const char Prefix = PrefixedName[0];
		if (Prefix != 'A' && Prefix != 'U')
			continue;

		PrefixCache.emplace(std::string(PrefixedName.substr(1)), std::pair<char, uint8_t>{ Prefix, 0 });
	}
}

std::string GetMangledFunctionNameForStaticclass(const std::string& ClassPrefixedName)
{
	// Windows UE binaries use the Microsoft C++ ABI. StaticClass is a public
	// static member returning UClass* and taking no arguments.
	return "?StaticClass@" + ClassPrefixedName + "@@SAPEAVUClass@@XZ";
}

void SetStaticClassNameAndSignature(func_t* Function, const std::string& ClassPrefixedName, tinfo_t& StaticClassFuncType)
{
	set_name(
		Function->start_ea,
		GetMangledFunctionNameForStaticclass(ClassPrefixedName).c_str(),
		SN_NOCHECK | SN_NOWARN | SN_FORCE);

	tinfo_t FuncType;
	if (!get_tinfo(&FuncType, Function->start_ea))
	{
		// No type info yet — try to guess it first
		guess_tinfo(&FuncType, Function->start_ea);
	}

	apply_tinfo(Function->start_ea, StaticClassFuncType, TINFO_DEFINITE);
}

/**
 * Builds a function signature: UClass* FunctionName();
 * Matches Unreal Engine coding style.
 */
tinfo_t BuildStaticClassFuncType()
{
	tinfo_t UClassType;
	// Attempt to locate UClass in the IDB's type library.
	if (!UClassType.get_named_type(get_idati(), "UClass"))
	{
		UClassType.create_forward_decl(get_idati(), BTF_STRUCT, "UClass");
	}

	// Convert UClass to UClass*
	UClassType.create_ptr(UClassType);

	// Prepare the function prototype data.
	func_type_data_t FuncData;
	FuncData.clear();            // start from an empty prototype (no arguments)
	FuncData.rettype = UClassType;

	// Create the final function tinfo_t.
	tinfo_t FuncType;
	if (!FuncType.create_func(FuncData))
	{
		msg("Error: Failed to create function signature object.\n");
	}

	return FuncType;
}

std::unordered_set<func_t*> GetReferenceStaticClassFunctions()
{
	const std::vector<ea_t> EngineStrAddrs = FindWideStringLiteralsByContent("/Script/Engine");
	const std::vector<ea_t> ActorComponentStrAddrs = FindWideStringLiteralsByContent("ActorComponent");
	const std::vector<ea_t> SceneComponentStrAddrs = FindWideStringLiteralsByContent("SceneComponent");
	const std::vector<ea_t> PrimitiveComponentStrAddrs = FindWideStringLiteralsByContent("PrimitiveComponent");
	const std::vector<ea_t> MeshComponentStrAddrs = FindWideStringLiteralsByContent("MeshComponent");

	if (EngineStrAddrs.empty())
	{
		msg("GetReferenceStaticClassFunctions: failed to find L\"/Script/Engine\".\n");
		return {};
	}

	if (ActorComponentStrAddrs.empty() || SceneComponentStrAddrs.empty() || PrimitiveComponentStrAddrs.empty() || MeshComponentStrAddrs.empty())
	{
		msg(
			"GetReferenceStaticClassFunctions: missing one or more reference class strings. "
			"ActorComponent=%d SceneComponent=%d PrimitiveComponent=%d MeshComponent=%d\n",
			static_cast<int>(ActorComponentStrAddrs.size()),
			static_cast<int>(SceneComponentStrAddrs.size()),
			static_cast<int>(PrimitiveComponentStrAddrs.size()),
			static_cast<int>(MeshComponentStrAddrs.size())
		);
	}

	// All refs to L"/Script/Engine", which is used in a lot of StaticClass functions
	std::unordered_set<func_t*>		  EngineStrRefs = GetFunctionsReferencingAnyAddress(EngineStrAddrs);
	const std::unordered_set<func_t*> ActorComponentStrRefs = GetFunctionsReferencingAnyAddress(ActorComponentStrAddrs);
	const std::unordered_set<func_t*> SceneComponentEngineStrRefs = GetFunctionsReferencingAnyAddress(SceneComponentStrAddrs);
	const std::unordered_set<func_t*> PrimitiveComponentStrRefs = GetFunctionsReferencingAnyAddress(PrimitiveComponentStrAddrs);
	const std::unordered_set<func_t*> MeshComponentStrRefs = GetFunctionsReferencingAnyAddress(MeshComponentStrAddrs);

	// Check all references to L"/Script/Engine" and see if they contain one of the
	// reference class names. Some game builds omit or merge all of those literals, so
	// retain every Engine-package user as a discovery fallback in that case.
	std::erase_if(EngineStrRefs, [&](func_t* RefFunc) -> bool
		{
			return !ActorComponentStrRefs.contains(RefFunc) && !SceneComponentEngineStrRefs.contains(RefFunc) && !PrimitiveComponentStrRefs.contains(RefFunc) && !MeshComponentStrRefs.contains(RefFunc);
		});
	if (EngineStrRefs.empty())
	{
		msg(
			"GetReferenceStaticClassFunctions: reference class anchors did not identify a StaticClass function; "
			"falling back to all L\"/Script/Engine\" users.\n"
		);
		return GetFunctionsReferencingAnyAddress(EngineStrAddrs);
	}

	return EngineStrRefs; // At this point EngineStrRefs is a set of only StaticClass functions
}

ea_t GetMostReferencedFunctionInStaticClass()
{
	// Maps a called function to how many StaticClass functions call it
	std::unordered_map<ea_t, size_t> ReferencedFunctionAndRefCount;

	for (auto* StaticClassFunc : GetReferenceStaticClassFunctions())
	{
		auto FunctionsCalledByStaticClass = GetCallTargetsInFunc(StaticClassFunc);
		for (auto FunctionCalledByStaticClass : FunctionsCalledByStaticClass)
		{
			ReferencedFunctionAndRefCount[FunctionCalledByStaticClass]++;
		}
	}

	ea_t FuncWithMostReferences = BADADDR;
	size_t MaxNumRefsEncountered = 0;
	for (auto [ReferencedFunctionAddress, RefCount] : ReferencedFunctionAndRefCount)
	{
		if (RefCount > MaxNumRefsEncountered)
		{
			FuncWithMostReferences = ReferencedFunctionAddress;
			MaxNumRefsEncountered = RefCount;
		}
	}
	return FuncWithMostReferences;
}

bool NameAllStaticClassFunctions()
{
	tinfo_t StaticClassFuncType = BuildStaticClassFuncType();

	ea_t LikelyGetPrivateStaticClassBody = GetMostReferencedFunctionInStaticClass();

	if (LikelyGetPrivateStaticClassBody == BADADDR)
		return false;

	// The shared body every StaticClass() forwards to is UE GetPrivateStaticClassBody
	set_name(LikelyGetPrivateStaticClassBody, "GetPrivateStaticClassBody", SN_NOCHECK | SN_NOWARN | SN_FORCE);

	std::unordered_set<func_t*> AllStaticClassFunctions = GetFunctionsReferencingThisFunction(LikelyGetPrivateStaticClassBody);

	int NumNonInlinedStaticClassCandidates = 0x0;
	int NumNamedStaticClasses = 0x0;
	for (auto* StaticClassFunc : AllStaticClassFunctions)
	{
		if (!IsLikelyNonInlinedStaticClass(StaticClassFunc))
			continue; // Some StaticClass calls are inlined and therefore substantially bigger than the average 0xB8 bytes

		NumNonInlinedStaticClassCandidates++;

		std::string ObjectName = GetStaticClassNameFromBodyCall(StaticClassFunc, LikelyGetPrivateStaticClassBody);
		if (ObjectName.empty())
		{
			msg("Skipping StaticClassFunc 0x%llX: could not read class name argument.\n", StaticClassFunc->start_ea);
			continue;
		}
		SetStaticClassNameAndSignature(StaticClassFunc, GetPrefixedName(ObjectName), StaticClassFuncType);
		NumNamedStaticClasses++;
	}

	msg("NumStaticClassCandidates: %d\n", NumNonInlinedStaticClassCandidates);
	msg("NumNamedStaticClasses: %d\n", NumNamedStaticClasses);

	return NumNamedStaticClasses > 0;
}
