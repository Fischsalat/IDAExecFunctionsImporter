#include "FNameConstantNamer.hpp"

#include <unordered_map>
#include <string>
#include <utility>
#include <unordered_set>
#include <cstdint>
#include <optional>
#include <vector>
#include <bit>

#include <ida.hpp>
#include <funcs.hpp>
#include <name.hpp>
#include <typeinf.hpp>

#include "Utility.hpp"

/*
 * Note: The content of both FNameConstantNamer.hpp and FNameConstantNamer.cpp is AI generated
 */

static constexpr const char* NameFNameGlobalsActionName = "idaexecfunctions:name-fname-constructor-globals";
static constexpr const char* NameFNameGlobalsActionHotkey = "Ctrl+Alt+F";

enum class ERecoveredFNameArgument : uint8_t
{
	Unseen,
	Resolved,
	Blocked
};

struct FNameConstructorArguments
{
	ea_t Destination = BADADDR;
	ea_t WideName = BADADDR;
	int FindType = -1;
};

enum class EFNameConstructorKind : uint8_t
{
	TwoArguments,
	ThreeArguments
};

struct FNameConstructorInfo
{
	ea_t Address = BADADDR;
	EFNameConstructorKind Kind = EFNameConstructorKind::ThreeArguments;
};

static bool IsRegisterOperand(const op_t& Operand, const char* RegisterName)
{
	if (Operand.type != o_reg)
		return false;

	qstring ActualName;
	const size_t Width = get_dtype_size(Operand.dtype);
	if (get_reg_name(&ActualName, Operand.reg, Width != 0 ? Width : 1) <= 0)
		return false;

	return strieq(ActualName.c_str(), RegisterName);
}

static bool IsAnyRegisterOperand(const op_t& Operand, const char* Register64, const char* Register32)
{
	return IsRegisterOperand(Operand, Register64) || IsRegisterOperand(Operand, Register32);
}

static ea_t GetAddressOperandValue(const op_t& Operand)
{
	switch (Operand.type)
	{
	case o_mem:
	case o_displ:
	case o_near:
	case o_far:
		return Operand.addr;
	case o_imm:
		return static_cast<ea_t>(Operand.value);
	default:
		return BADADDR;
	}
}

static std::optional<std::wstring> ReadWideName(ea_t Address)
{
	if (Address == BADADDR || getseg(Address) == nullptr)
		return std::nullopt;

	std::wstring Result;
	for (size_t Index = 0; Index < 1024; ++Index)
	{
		const uint16 Character = get_word(Address + Index * sizeof(uint16));
		if (Character == 0)
			return Result.empty() ? std::nullopt : std::optional<std::wstring>(std::move(Result));

		// FNames may contain spaces and punctuation, but not control characters.
		if (Character < 0x20 || Character == 0x7F)
			return std::nullopt;

		Result.push_back(static_cast<wchar_t>(Character));
	}

	return std::nullopt;
}

static std::optional<FNameConstructorArguments> RecoverFNameConstructorArguments(ea_t ReferenceEa, EFNameConstructorKind Kind)
{
	func_t* Function = get_func(ReferenceEa);
	if (!Function)
		return std::nullopt;

	FNameConstructorArguments Arguments;
	ERecoveredFNameArgument DestinationState = ERecoveredFNameArgument::Unseen;
	ERecoveredFNameArgument WideNameState = ERecoveredFNameArgument::Unseen;
	ERecoveredFNameArgument FindTypeState = ERecoveredFNameArgument::Unseen;

	ea_t Address = ReferenceEa;
	for (size_t InstructionCount = 0; InstructionCount < 32 && Address > Function->start_ea; ++InstructionCount)
	{
		Address = prev_head(Address, Function->start_ea);
		if (Address == BADADDR || Address < Function->start_ea)
			break;

		insn_t Insn;
		if (decode_insn(&Insn, Address) <= 0)
			break;

		// Calls clobber the volatile argument registers. Never recover values across one.
		if (is_call_insn(Insn))
			break;

		qstring Mnemonic;
		if (!print_insn_mnem(&Mnemonic, Address))
			continue;

		const bool IsMove = strieq(Mnemonic.c_str(), "mov");
		const bool IsLea = strieq(Mnemonic.c_str(), "lea");
		const bool IsXor = strieq(Mnemonic.c_str(), "xor");
		const bool ChangesFirstOperand = (Insn.get_canon_feature(PH) & CF_CHG1) != 0;

		auto RecoverAddress = [&](ERecoveredFNameArgument& State, ea_t& Value)
		{
			if (State != ERecoveredFNameArgument::Unseen || !ChangesFirstOperand)
				return;

			if ((IsMove || IsLea) && Insn.ops[1].type != o_reg)
			{
				Value = GetAddressOperandValue(Insn.ops[1]);
				State = Value == BADADDR ? ERecoveredFNameArgument::Blocked : ERecoveredFNameArgument::Resolved;
			}
			else
			{
				State = ERecoveredFNameArgument::Blocked;
			}
		};

		if (IsAnyRegisterOperand(Insn.ops[0], "rcx", "ecx"))
		{
			RecoverAddress(DestinationState, Arguments.Destination);
		}
		else if (IsAnyRegisterOperand(Insn.ops[0], "rdx", "edx"))
		{
			RecoverAddress(WideNameState, Arguments.WideName);
		}
		else if (IsAnyRegisterOperand(Insn.ops[0], "r8", "r8d") && FindTypeState == ERecoveredFNameArgument::Unseen && ChangesFirstOperand)
		{
			if (IsMove && Insn.ops[1].type == o_imm && Insn.ops[1].value <= 1)
			{
				Arguments.FindType = static_cast<int>(Insn.ops[1].value);
				FindTypeState = ERecoveredFNameArgument::Resolved;
			}
			else if (IsXor && IsAnyRegisterOperand(Insn.ops[1], "r8", "r8d"))
			{
				Arguments.FindType = 0;
				FindTypeState = ERecoveredFNameArgument::Resolved;
			}
			else
			{
				FindTypeState = ERecoveredFNameArgument::Blocked;
			}
		}

		const bool HasRequiredFindType = Kind == EFNameConstructorKind::TwoArguments
			|| FindTypeState == ERecoveredFNameArgument::Resolved;
		if (DestinationState == ERecoveredFNameArgument::Resolved
			&& WideNameState == ERecoveredFNameArgument::Resolved
			&& HasRequiredFindType)
		{
			return Arguments;
		}

		if (is_basic_block_end(Insn, false))
			break;
	}

	return std::nullopt;
}

static qstring MakeFNameGlobalName(const std::wstring& WideName)
{
	qstring Name(("NAME_" + WStrToStr(WideName)).c_str());
	validate_name(&Name, VNT_IDENT, SN_NOCHECK);
	return Name;
}

static ea_t GetDirectCallOrTailTarget(const insn_t& Insn)
{
	if (Insn.ops[0].type != o_near && Insn.ops[0].type != o_far)
		return BADADDR;

	const uint32 Features = Insn.get_canon_feature(PH);
	return is_call_insn(Insn) || (Features & CF_STOP) != 0 ? Insn.ops[0].addr : BADADDR;
}

struct FNameConstructorCandidateStats
{
	size_t TwoArgumentCalls = 0;
	size_t ThreeArgumentCalls = 0;
	uint32_t TwoArgumentAnchors = 0;
	uint32_t ThreeArgumentAnchors = 0;
};

static std::optional<FNameConstructorInfo> SelectFNameConstructorCandidate(
	const std::unordered_map<ea_t, FNameConstructorCandidateStats>& Candidates,
	EFNameConstructorKind Kind)
{
	ea_t BestAddress = BADADDR;
	size_t BestAnchorCount = 0;
	size_t BestCallCount = 0;
	bool IsAmbiguous = false;

	for (const auto& [Address, Stats] : Candidates)
	{
		const uint32_t Anchors = Kind == EFNameConstructorKind::ThreeArguments
			? Stats.ThreeArgumentAnchors
			: Stats.TwoArgumentAnchors;
		const size_t CallCount = Kind == EFNameConstructorKind::ThreeArguments
			? Stats.ThreeArgumentCalls
			: Stats.TwoArgumentCalls;
		const size_t AnchorCount = static_cast<size_t>(std::popcount(Anchors));
		if (CallCount == 0)
			continue;

		if (AnchorCount > BestAnchorCount || (AnchorCount == BestAnchorCount && CallCount > BestCallCount))
		{
			BestAddress = Address;
			BestAnchorCount = AnchorCount;
			BestCallCount = CallCount;
			IsAmbiguous = false;
		}
		else if (AnchorCount == BestAnchorCount && CallCount == BestCallCount)
		{
			IsAmbiguous = true;
		}
	}

	if (BestAddress == BADADDR || IsAmbiguous)
		return std::nullopt;

	msg(
		"[IDAMappingsImporter] Identified %s at 0x%llX from %llu validated call(s) across %llu anchor(s).\n",
		Kind == EFNameConstructorKind::ThreeArguments ? "FName::FName(Name, FindType)" : "FName::FName(Name)",
		BestAddress,
		static_cast<unsigned long long>(BestCallCount),
		static_cast<unsigned long long>(BestAnchorCount)
	);
	return FNameConstructorInfo{ BestAddress, Kind };
}

static std::vector<FNameConstructorInfo> FindFNameConstructors()
{
	struct Anchor
	{
		const char* Text;
		uint32_t Bit;
	};
	const Anchor Anchors[] =
	{
		{ "DiffuseColor", 1 },
		{ "SwitchDefault", 2 },
		// Common in non-trivial static-initializer functions where the FName
		// construction is followed by unrelated initialization and atexit work.
		{ "BootGlobal", 4 },
		// Often initialized in a separate guarded block in the same function.
		{ "Reset", 8 }
	};

	std::unordered_map<ea_t, FNameConstructorCandidateStats> Candidates;
	for (const Anchor& CurrentAnchor : Anchors)
	{
		const std::vector<ea_t> AnchorStrings = FindWideStringLiteralsByContent(CurrentAnchor.Text);
		std::unordered_set<ea_t> ScannedFunctions;
		for (const ea_t AnchorString : AnchorStrings)
		{
			xrefblk_t StringXref;
			for (bool Ok = StringXref.first_to(AnchorString, XREF_ALL); Ok; Ok = StringXref.next_to())
			{
				func_t* Function = get_func(StringXref.from);
				if (!Function || !ScannedFunctions.insert(Function->start_ea).second)
					continue;

				for (ea_t Address = Function->start_ea; Address < Function->end_ea; Address = next_head(Address, Function->end_ea))
				{
					insn_t Insn;
					if (!is_code(get_flags(Address)) || decode_insn(&Insn, Address) <= 0)
						continue;

					const ea_t Target = GetDirectCallOrTailTarget(Insn);
					if (Target == BADADDR || !IsValidCodePointer(Target))
						continue;

					std::optional<FNameConstructorArguments> Arguments = RecoverFNameConstructorArguments(
						Address,
						EFNameConstructorKind::ThreeArguments);
					EFNameConstructorKind Kind = EFNameConstructorKind::ThreeArguments;
					if (!Arguments || Arguments->WideName != AnchorString || (Arguments->FindType != 0 && Arguments->FindType != 1))
					{
						Arguments = RecoverFNameConstructorArguments(Address, EFNameConstructorKind::TwoArguments);
						Kind = EFNameConstructorKind::TwoArguments;
					}

					if (!Arguments || Arguments->WideName != AnchorString)
						continue;

					segment_t* DestinationSegment = getseg(Arguments->Destination);
					if (!DestinationSegment || (DestinationSegment->perm & SEGPERM_WRITE) == 0)
						continue;

					FNameConstructorCandidateStats& Stats = Candidates[Target];
					if (Kind == EFNameConstructorKind::ThreeArguments)
					{
						++Stats.ThreeArgumentCalls;
						Stats.ThreeArgumentAnchors |= CurrentAnchor.Bit;
					}
					else
					{
						++Stats.TwoArgumentCalls;
						Stats.TwoArgumentAnchors |= CurrentAnchor.Bit;
					}
				}
			}
		}
	}

	std::vector<FNameConstructorInfo> Result;
	if (const auto ThreeArgument = SelectFNameConstructorCandidate(Candidates, EFNameConstructorKind::ThreeArguments))
		Result.push_back(*ThreeArgument);
	if (const auto TwoArgument = SelectFNameConstructorCandidate(Candidates, EFNameConstructorKind::TwoArguments))
		Result.push_back(*TwoArgument);

	if (Result.empty())
		msg("[IDAMappingsImporter] Could not identify an FName constructor from L\"DiffuseColor\", L\"SwitchDefault\", L\"BootGlobal\", or L\"Reset\".\n");
	return Result;
}

static ea_t GetFNameConstructorTargetFromCursor()
{
	const ea_t CursorEa = get_screen_ea();
	if (CursorEa == BADADDR)
		return BADADDR;

	insn_t Insn;
	if (decode_insn(&Insn, CursorEa) > 0)
	{
		const ea_t Target = GetDirectCallOrTailTarget(Insn);
		if (Target != BADADDR)
			return Target;
	}

	func_t* Function = get_func(CursorEa);
	return Function ? Function->start_ea : BADADDR;
}

static std::optional<FNameConstructorInfo> ClassifyFNameConstructor(ea_t ConstructorEa)
{
	xrefblk_t Xref;
	for (bool Ok = Xref.first_to(ConstructorEa, XREF_ALL); Ok; Ok = Xref.next_to())
	{
		if (const auto ThreeArguments = RecoverFNameConstructorArguments(Xref.from, EFNameConstructorKind::ThreeArguments))
		{
			if (ThreeArguments->FindType == 0 || ThreeArguments->FindType == 1)
				return FNameConstructorInfo{ ConstructorEa, EFNameConstructorKind::ThreeArguments };
		}
		if (RecoverFNameConstructorArguments(Xref.from, EFNameConstructorKind::TwoArguments))
			return FNameConstructorInfo{ ConstructorEa, EFNameConstructorKind::TwoArguments };
	}
	return std::nullopt;
}

static bool ApplyFNameConstructorNameAndType(const FNameConstructorInfo& Constructor, bool HasFNameType)
{
	const bool HasFindType = Constructor.Kind == EFNameConstructorKind::ThreeArguments;
	const char* DecoratedName = HasFindType
		? "??0FName@@QEAA@PEB_WW4EFindName@@@Z"
		: "??0FName@@QEAA@PEB_W@Z";
	const char* Declaration = HasFindType
		? (HasFNameType
			? "FName *__fastcall FName__FName(FName *this, const wchar_t *Name, unsigned int FindType);"
			: "void *__fastcall FName__FName(void *this, const wchar_t *Name, unsigned int FindType);")
		: (HasFNameType
			? "FName *__fastcall FName__FName(FName *this, const wchar_t *a2);"
			: "void *__fastcall FName__FName(void *this, const wchar_t *a2);");

	const bool NameApplied = set_name(Constructor.Address, DecoratedName, SN_NOCHECK | SN_NOWARN | SN_FORCE);
	tinfo_t ConstructorType;
	qstring ParsedName;
	if (!parse_decl(&ConstructorType, &ParsedName, get_idati(), Declaration, PT_SIL | PT_VAR | PT_HIGH | PT_RELAXED | PT_SEMICOLON))
	{
		msg("[IDAMappingsImporter] Failed to parse FName constructor declaration: %s\n", Declaration);
		return false;
	}

	const bool TypeApplied = apply_tinfo(Constructor.Address, ConstructorType, TINFO_DEFINITE);
	if (!NameApplied || !TypeApplied)
		msg("[IDAMappingsImporter] Failed to fully annotate FName constructor at 0x%llX.\n", Constructor.Address);
	return NameApplied && TypeApplied;
}

static size_t NameGlobalsForFNameConstructor(
	const FNameConstructorInfo& Constructor,
	const tinfo_t& FNameType,
	bool HasFNameType,
	size_t& RenamedCount,
	size_t& TypedCount)
{
	size_t CandidateCount = 0;
	xrefblk_t Xref;
	for (bool Ok = Xref.first_to(Constructor.Address, XREF_ALL); Ok; Ok = Xref.next_to())
	{
		insn_t ReferenceInsn;
		if (!is_code(get_flags(Xref.from))
			|| decode_insn(&ReferenceInsn, Xref.from) <= 0
			|| GetDirectCallOrTailTarget(ReferenceInsn) != Constructor.Address)
			continue;

		const std::optional<FNameConstructorArguments> Arguments = RecoverFNameConstructorArguments(Xref.from, Constructor.Kind);
		if (!Arguments)
			continue;
		if (Constructor.Kind == EFNameConstructorKind::ThreeArguments
			&& Arguments->FindType != 0 && Arguments->FindType != 1)
			continue;

		segment_t* DestinationSegment = getseg(Arguments->Destination);
		if (!DestinationSegment || !(DestinationSegment->perm & SEGPERM_WRITE))
			continue;

		const std::optional<std::wstring> WideName = ReadWideName(Arguments->WideName);
		if (!WideName)
			continue;

		++CandidateCount;
		const qstring GlobalName = MakeFNameGlobalName(*WideName);
		if (!GlobalName.empty() && set_name(Arguments->Destination, GlobalName.c_str(), SN_NOCHECK | SN_NOWARN | SN_FORCE))
			++RenamedCount;

		if (HasFNameType && apply_tinfo(Arguments->Destination, FNameType, TINFO_DEFINITE))
			++TypedCount;
	}

	msg(
		"[IDAMappingsImporter] FName constructor 0x%llX: found %llu matching globals.\n",
		Constructor.Address,
		static_cast<unsigned long long>(CandidateCount)
	);
	return CandidateCount;
}

bool NameAllFNameConstructorGlobals(bool AllowCursorFallback)
{
	std::vector<FNameConstructorInfo> Constructors = FindFNameConstructors();
	if (Constructors.empty() && AllowCursorFallback)
	{
		const ea_t CursorTarget = GetFNameConstructorTargetFromCursor();
		if (CursorTarget != BADADDR)
		{
			if (const auto Constructor = ClassifyFNameConstructor(CursorTarget))
				Constructors.push_back(*Constructor);
		}
	}

	if (Constructors.empty())
	{
		if (AllowCursorFallback)
			warning("Could not find FName::FName. Place the cursor on it or on a direct call/jump to it and retry.");
		return false;
	}

	// Deliberately perform this lookup exactly once for the complete batch.
	tinfo_t FNameType;
	const bool HasFNameType = FNameType.get_named_type(get_idati(), "FName");

	size_t CandidateCount = 0;
	size_t RenamedCount = 0;
	size_t TypedCount = 0;
	for (const FNameConstructorInfo& Constructor : Constructors)
	{
		ApplyFNameConstructorNameAndType(Constructor, HasFNameType);
		CandidateCount += NameGlobalsForFNameConstructor(Constructor, FNameType, HasFNameType, RenamedCount, TypedCount);
	}

	msg(
		"[IDAMappingsImporter] FName pass: %llu constructor(s), %llu globals, %llu renamed, %llu typed%s.\n",
		static_cast<unsigned long long>(Constructors.size()),
		static_cast<unsigned long long>(CandidateCount),
		static_cast<unsigned long long>(RenamedCount),
		static_cast<unsigned long long>(TypedCount),
		HasFNameType ? "" : " (using void* constructor signatures; FName type not present)"
	);
	refresh_idaview_anyway();
	return CandidateCount != 0;
}
