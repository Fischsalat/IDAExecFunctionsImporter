#include <fstream>
#include <vector>
#include <cstring>
#include <optional>
#include <unordered_set>
#include <filesystem>
#include <stop_token>

#define __EA64__

#include <ida.hpp>
#include <idp.hpp>
#include <loader.hpp>
#include <kernwin.hpp>
#include <name.hpp>
#include <nalt.hpp>
#include <typeinf.hpp>
#include <srclang.hpp>

#include <Format/IDAMappingLayout.hpp>
#include <Format/Parser.hpp>
#include <Import/MappingsImporter.hpp>
#include <Import/ExecRename.hpp>
#include <Import/ExecSignatures.hpp>

#include "StaticClassNamer.hpp"
#include "FNameConstantNamer.hpp"


namespace fs = std::filesystem;

enum class EAvailableFoldersStatus : uint8
{
	None,        // neither subfolder present, or the selection was invalid
	All,         // both CppSDK and IDAMappings are present
	CppSDK,      // only CppSDK is present
	IDAMappings  // only IDAMappings is present
};

fs::path GetDefaultDumperOutputPath()
{
#ifdef __NT__
	return "C:\\Dumper-7\\";
#else
	// Dumper-7 is Windows-only. The only way to use it on Linux is through
	// a Wine/Proton prefix at an unpredictable path. Leaving the function
	// here in case Linux support with unified path is added in the future.
	return {};
#endif
}

std::pair<fs::path, EAvailableFoldersStatus> AskForSDKFolder(fs::path DefaultPath)
{
	qstring FolderQStr = DefaultPath.string().c_str();

	if (!ask_str(&FolderQStr, HIST_DIR, "Please select a folder containing \"CppSDK\" and \"IDAMappings\" subfolders."))
		return std::pair{ std::string{}, EAvailableFoldersStatus::None };

	fs::path Folder;
	Folder = FolderQStr.c_str();

	fs::path CppSDKPath = Folder / "CppSDK";
	fs::path IDAMappingsPath = Folder / "IDAMappings";

	const bool bhasCppSDKFolder      = fs::exists(CppSDKPath) && fs::is_directory(Folder / "CppSDK");
	const bool bhasIDAMappingsFolder = fs::exists(IDAMappingsPath) && fs::is_directory(Folder / "IDAMappings");

	if (!fs::exists(Folder) || !fs::is_directory(Folder) || (!bhasCppSDKFolder && !bhasIDAMappingsFolder))
	{
		warning("Please select the top level generated folder for your game that contains 'CppSDK' and 'IDAMappings'. Eg.'5.7.2-0+UE5-GameName'");
		return std::pair{ fs::path{}, EAvailableFoldersStatus::None };
	}

	if (!bhasCppSDKFolder)
	{
		warning("Selected folder doesn't contain 'CppSDK' folder, importing SDK.hpp into IDA won't be available.");
		return std::pair{ Folder, EAvailableFoldersStatus::IDAMappings };
	}

	if (!bhasIDAMappingsFolder)
	{
		warning("Selected folder doesn't contain 'IDAMappings' folder, importing VTables, ExecFunctions and global variables won't be available.");
		return std::pair{ Folder, EAvailableFoldersStatus::CppSDK };
	}

	return std::pair{ Folder, EAvailableFoldersStatus::All };
}

struct CppSDKImportCheck
{
public:
	friend bool ParseSDKHeaderWithClang(const fs::path& HeaderPath, bool bForceImport);

	static constexpr const char* ImportFlagTypeName = "YesWeImportedTheCppSDK";

	static inline void CreateImportFlagType()
	{
		udt_type_data_t Udt;
		Udt.total_size = 1;
		Udt.unpadded_size = 1;
		Udt.taudt_bits |= TAUDT_CPPOBJ;
		tinfo_t Type;
		if (Type.create_udt(Udt, BTF_STRUCT))
			Type.set_named_type(nullptr, ImportFlagTypeName, NTF_TYPE);
	}

	static inline bool HasImportFlagType()
	{
		tinfo_t TestType;
		return TypeHelpers::LookupType(ImportFlagTypeName, TestType);
	}
};


bool ParseSDKHeaderWithClang(const fs::path& HeaderPath, bool bForceImport = false)
{
	if (!select_parser_by_srclang(SRCLANG_CPP))
		return false;

	if (GHasCppSDKTypes && !bForceImport)
		return true; // Already imported, no need to re-import

	GHasCppSDKTypes = CppSDKImportCheck::HasImportFlagType();

	if (GHasCppSDKTypes && !bForceImport)
		return true; // Already imported, no need to re-import

	constexpr const char* ClangArgs = "-std=c++20 -Wno-invalid-offsetof -Wno-c++11-narrowing -D IMPORT_CPP_SDK_INTO_IDA=1";

	const int ParserErrorCode = set_parser_argv("clang", ClangArgs);
	if (ParserErrorCode != 0)
	{
		msg("ParseSDKHeaderWithClang: failed to set parser argv. ErrorCode: %d\n", ParserErrorCode);
		return false;
	}

	// Create a dummy type so we can later look up whether the CppSDK was imported or not.
	CppSDKImportCheck::CreateImportFlagType();


	// nullptr for til => import straight into the current IDB
	const int NumCompilerErrors = parse_decls_with_parser("clang", nullptr, HeaderPath.string().c_str(), true);

	if (NumCompilerErrors == -1)
	{
		msg("ParseSDKHeaderWithClang: parser not found - is idaclang plugin loaded?\n");
		return false;
	}

	msg("ParseSDKHeaderWithClang: parsed '%s' with %d error(s)\n", HeaderPath.string().c_str(), NumCompilerErrors);
	return NumCompilerErrors == 0;
}

struct VTableEntry
{
	ea_t SlotAddress;   // address of the pointer slot in the vtable
	ea_t FuncAddress;   // address of the actual function
	int  Index;
};

static void IterateVTable(ea_t VTableAddress, std::function<void(const VTableEntry&)> Callback)
{
	const int PtrSize = inf_is_64bit() ? 8 : 4;
	int Index = 0;

	while (true)
	{
		ea_t SlotAddress = VTableAddress + (Index * PtrSize);

		// Stop at the next named item (new VTable, function, data symbol, etc.)
		if (Index > 0 && has_name(get_flags(SlotAddress)))
			break;

		ea_t FuncAddress = (PtrSize == 8)
			? get_qword(SlotAddress)
			: get_dword(SlotAddress);

		// Must point into a code segment
		segment_t* TargetSeg = getseg(FuncAddress);
		if (!TargetSeg || TargetSeg->sclass != SEG_CODE)
			break;

		// Slot itself must be a defined head (IDA has analysed it as data)
		if (Index > 0 && !is_head(get_flags(SlotAddress)))
			break;

		Callback({ SlotAddress, FuncAddress, Index });
		Index++;
	}
}

void SetFunctionThisPtrType(ea_t FuncAddress, tinfo_t ThisType)
{
	// Get the existing function type
	tinfo_t FuncType;
	if (!get_tinfo(&FuncType, FuncAddress))
	{
		// No type info yet, guess it from analysis
		guess_tinfo(&FuncType, FuncAddress);
	}

	func_type_data_t FuncData;
	if (!FuncType.get_func_details(&FuncData))
	{
		msg("Failed to get func details at 0x%llX\n", (uint64)FuncAddress);
		return;
	}

	// First arg is `this` for non-static member functions
	if (FuncData.empty())
	{
		// No args at all, insert one
		funcarg_t ThisArg;
		ThisArg.type = ThisType;
		ThisArg.name = "this";
		FuncData.push_back(ThisArg);
	}
	else
	{
		const tinfo_t& FirstArgType = FuncData[0].type;

		// Skip if the first parameter is already a pointer to a struct/class
		if (FirstArgType.is_ptr())
		{
			const tinfo_t PointeeType = FirstArgType.get_pointed_object();
			if (PointeeType.is_struct())
			{
				return;
			}
		}
		FuncData[0].type = ThisType;
		FuncData[0].name = "this";
	}

	FuncType.create_func(FuncData);
	apply_tinfo(FuncAddress, FuncType, TINFO_DEFINITE);
}

static void HandleVTableThisPtrRename(ea_t VTableAddress, ea_t SuperVTableAddress, std::string TypeName)
{
	tinfo_t StructType;
	if (!StructType.get_named_type(get_idati(), TypeName.c_str()))
		return; // type not imported (e.g. SDK.hpp not parsed) -> skip this-ptr typing silently

	tinfo_t ThisType;
	ThisType.create_ptr(StructType);

	auto CallSetFunctionThisPtr = [&](const VTableEntry& Entry)
	{
		const ea_t SuperFuncAddressSlot = SuperVTableAddress + Entry.Index * (inf_is_64bit() ? 8 : 4);

		if (SuperVTableAddress && Entry.FuncAddress == get_qword(SuperFuncAddressSlot))
		{
			return;
		}

		SetFunctionThisPtrType(Entry.FuncAddress, ThisType);
	};

	IterateVTable(VTableAddress, CallSetFunctionThisPtr);
}

static void LoadOldMapping(const std::vector<uint8_t>& Buffer, ea_t ImageBase)
{
	size_t Position = 0;
	const size_t Size = Buffer.size();

	while (Position + sizeof(uint32_t) + sizeof(uint16_t) <= Size)
	{
		uint32_t Offset;
		memcpy(&Offset, Buffer.data() + Position, sizeof(Offset));
		Position += sizeof(Offset);

		uint16_t NameLength;
		memcpy(&NameLength, Buffer.data() + Position, sizeof(NameLength));
		Position += sizeof(NameLength);

		if (Position + NameLength > Size)
			break;

		std::string Name(reinterpret_cast<const char*>(Buffer.data() + Position), NameLength);
		Position += NameLength;

		set_name(ImageBase + Offset, Name.c_str(), SN_NOCHECK | SN_NOWARN | SN_FORCE);

		if (Name.ends_with("_VFT"))
			HandleVTableThisPtrRename(ImageBase + Offset, 0, Name.substr(0, Name.length() - 4));
	}
}

bool ReadAndParseIDAMappings(const fs::path& IDAMappingsFilePath, bool bImportTypes)
{
	std::ifstream IDAMappingsFile(IDAMappingsFilePath, std::ios::binary | std::ios::ate);
	if (!IDAMappingsFile)
	{
		msg("[IDAMappingsImporter] Failed to open file!\n");
		return false;
	}

	const auto IDAMappingsFileSize = IDAMappingsFile.tellg();
	std::vector<uint8_t> Buffer(IDAMappingsFileSize);
	IDAMappingsFile.seekg(0);
	IDAMappingsFile.read(reinterpret_cast<char*>(Buffer.data()), IDAMappingsFileSize);

	const ea_t ImageBase = get_imagebase();

	if (!Buffer.empty() && Buffer[0] == IDAMappingsLayouts::FileMagic)
	{
		// Validate the full header (magic, version, section bounds) before trusting any offsets
		MappingParser PrefixParser(Buffer);
		if (!PrefixParser.IsValidHeader())
		{
			msg("[IDAMappingsImporter] .idmap header is malformed. Aborting import!\n");
			return false;
		}

		msg("[IDAMappingsImporter] Loading V2 mapping file...\n");

		BuildStaticClassPrefixCache(PrefixParser);

		LoadMappings(std::move(Buffer), ImageBase, bImportTypes);
		if (SaveCurrentIdbSignaturesToIdb())
			msg("[IDAMappingsImporter] Persisted %zu exec signatures to IDB.\n", CurrentIdbSignatures().size());
	}
	else
	{
		msg("[IDAMappingsImporter] Loading V1 mapping file...\n");
		LoadOldMapping(Buffer, ImageBase);
	}

	msg("[IDAMappingsImporter] Done!\n");

	return true;
}

fs::path FindFileWithExtensionInPath(const fs::path& PathToSearch, std::string ExtensionString)
{
	if (!fs::exists(PathToSearch) || !fs::is_directory(PathToSearch))
	{
		return {};
	}

	// Normalize the extension: ensure it starts with a dot
	if (!ExtensionString.empty() && ExtensionString.front() != '.')
	{
		ExtensionString.insert(0, ".");
	}

	for (const fs::directory_entry& Entry : fs::recursive_directory_iterator(PathToSearch))
	{
		if (!Entry.is_regular_file())
		{
			continue;
		}

		if (Entry.path().extension() == ExtensionString)
		{
			return Entry.path();
		}
	}

	return {};
}

enum class ETypeSource
{
	Idaclang,
	Mappings,
	None
};

struct AskForSDKImportResult
{
	ETypeSource TypeSource;
	bool bIDAMappingsAvailable;
};

std::optional<AskForSDKImportResult> AskForSDKImport(EAvailableFoldersStatus FolderStatus)
{
	const bool bCppSDKAvailable = (FolderStatus == EAvailableFoldersStatus::All || FolderStatus == EAvailableFoldersStatus::CppSDK);
	const bool bIDAMappingsAvailable = (FolderStatus == EAvailableFoldersStatus::All || FolderStatus == EAvailableFoldersStatus::IDAMappings);

	qstrvec_t TypeChoices;
	std::vector<ETypeSource> TypeActions;

	if (bCppSDKAvailable)
	{
		TypeChoices.push_back("idaclang (recommended)");
		TypeActions.push_back(ETypeSource::Idaclang);
	}

	if (bIDAMappingsAvailable)
	{
		TypeChoices.push_back("Mappings");
		TypeActions.push_back(ETypeSource::Mappings);
	}

	TypeChoices.push_back("Don't import types");
	TypeActions.push_back(ETypeSource::None);

	static const char TypeSourceForm[] =
		"Import UE types\n"
		"\n"
		"Source for class/struct types (names + functions import either way):\n"
		"\n"
		"  <Type source:b1:0:50::>\n"
		"\n";

	int TypeSel = 0; // default: first (and recommended) available option
	if (ask_form(TypeSourceForm, &TypeChoices, &TypeSel) <= 0)
		return std::nullopt; // user cancelled

	if (TypeSel < 0 || TypeSel >= static_cast<int>(TypeActions.size()))
		return std::nullopt;

	return { { TypeActions[TypeSel], bIDAMappingsAvailable } };
}


struct IDAMappingsPlugin : public plugmod_t
{
	IDAMappingsPlugin()
	{
		GHasCppSDKTypes = CppSDKImportCheck::HasImportFlagType();
		LoadPersistedExecSignaturesFromIdb();
		InstallExecRenameAction();
	}

	~IDAMappingsPlugin()
	{
		UninstallExecRenameAction();
	}

	bool idaapi run(size_t) override
	{
		const auto [PathToDumperGeneratedDirectory, FolderStatus] = AskForSDKFolder(GetDefaultDumperOutputPath());

		if (FolderStatus == EAvailableFoldersStatus::None)
			return false;

		// idaclang is only offered when CppSDK is present which parses SDK.hpp for the types
		const auto SDKImportDialogueResult = AskForSDKImport(FolderStatus);
		if (!SDKImportDialogueResult)
			return false;

		const auto [TypeSource, bIDAMappingsAvailable] = *SDKImportDialogueResult;

		if (TypeSource == ETypeSource::Idaclang)
		{
			const fs::path SDKHeaderFilePath = PathToDumperGeneratedDirectory / "CppSDK" / "SDK.hpp";

			if (fs::exists(SDKHeaderFilePath))
				ParseSDKHeaderWithClang(SDKHeaderFilePath);
			else
				msg("[IDAMappingsImporter] CppSDK/SDK.hpp not found.\n");
		}

		ClearStaticClassPrefixCache(); // fresh per run since only the V2 path repopulates it
		CurrentIdbSignatures().clear(); // same deal: cleared every run so a V1/no-map import can't reuse stale V2 prototypes
		ClearPersistedExecSignatures();

		// Always import the .idmap when present (names / exec-funcs / globals) and only build types from it in Mappings mode
		if (bIDAMappingsAvailable)
		{
			const fs::path MappingFilePath = FindFileWithExtensionInPath(PathToDumperGeneratedDirectory / "IDAMappings", ".idmap");

			if (!MappingFilePath.empty())
				ReadAndParseIDAMappings(MappingFilePath, TypeSource == ETypeSource::Mappings);
		}

		if (!NameAllStaticClassFunctions())
		{
			msg("[IDAMappingsImporter] Failed to name all static class functions.\n");
		}

		if (!NameAllFNameConstructorGlobals())
		{
			msg("[IDAMappingsImporter] Failed to name all FName constructor globals.\n");
		}

		return true;
	}
};

static plugmod_t* idaapi init()
{
	return new IDAMappingsPlugin();
}

plugin_t PLUGIN =
{
	IDP_INTERFACE_VERSION,
	PLUGIN_MULTI,
	init,
	nullptr,
	nullptr,
	"Load .idmap/.usmap mapping files",
	"IDA Mappings Importer - Load UE SDK mapping files",
	"IDA Mappings Importer",
	"Ctrl-Alt-D",
};
