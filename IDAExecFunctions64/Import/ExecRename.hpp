#pragma once

#include <cctype>
#include <string>

#include <kernwin.hpp>
#include <lines.hpp>
#include <loader.hpp>
#include <name.hpp>
#include <demangle.hpp>
#include <funcs.hpp>
#include <xref.hpp>
#include <idp.hpp>
#include <hexrays.hpp>

#include <Import/MappingsImporter.hpp>
#include <Import/ExecSignatures.hpp>
#include <Utility.hpp>

static const char ExecRenameActionName[] = "idamappings:rename_exec_target";
static const char ExecApplySignatureActionName[] = "idamappings:apply_exec_signature";

// "APawn::execGetLocalViewingPlayerController" -> "APawn::GetLocalViewingPlayerController"
// Returns an empty string when the last name component has no 'exec' prefix
inline std::string DeriveRealNameFromExecThunk(const std::string& RawThunkName)
{
	std::string ThunkName = RawThunkName;
	const size_t ParamStart = ThunkName.find('(');
	if (ParamStart != std::string::npos)
		ThunkName.erase(ParamStart);

	const size_t ScopeEnd = ThunkName.rfind("::");
	const size_t FuncStart = (ScopeEnd == std::string::npos) ? 0 : ScopeEnd + 2;

	const std::string Scope    = ThunkName.substr(0, FuncStart);
	const std::string FuncPart = ThunkName.substr(FuncStart);

	if (FuncPart.rfind("exec", 0) != 0 || FuncPart.length() <= 4)
		return std::string();

	return Scope + FuncPart.substr(4);
}

inline std::string StripReturnTypeSuffix(std::string Name, const std::string& ReturnType)
{
	const auto TryStrip = [&Name](const std::string& Token) -> bool
	{
		const std::string Suffix = "_" + Token + "_";

		if (Name.size() > Suffix.size() && Name.compare(Name.size() - Suffix.size(), Suffix.size(), Suffix) == 0)
		{
			Name.erase(Name.size() - Suffix.size());
			return true;
		}

		return false;
	};

	// Prefer the exact return type from the signature
	if (!ReturnType.empty())
	{
		std::string Bare = ReturnType;

		while (!Bare.empty() && (Bare.back() == '*' || Bare.back() == ' '))
			Bare.pop_back();

		if (TryStrip(Bare))
			return Name;
	}

	// Fallback to common primitive return types when no signature is available
	static const char* const Primitives[] = {
		"void", "bool", "char", "float", "double", "int",
		"int8", "int16", "int32", "int64", "uint8", "uint16", "uint32", "uint64",
	};

	for (const char* Token : Primitives)
		if (TryStrip(Token))
			return Name;

	return Name;
}

inline bool GetCurrentExecThunk(TWidget* Widget, func_t*& OutThunkFunction, qstring& OutThunkName)
{
	ea_t ThunkEA = get_screen_ea();

	if (vdui_t* View = get_widget_vdui(Widget))
	{
		if (View->cfunc != nullptr)
			ThunkEA = View->cfunc->entry_ea;
	}

	OutThunkFunction = get_func(ThunkEA);
	if (OutThunkFunction == nullptr)
	{
		msg("[IDAMappingsImporter] Not inside a function.\n");
		return false;
	}

	get_func_name(&OutThunkName, OutThunkFunction->start_ea);

	qstring DemangledThunkName;
	if (demangle_name(&DemangledThunkName, OutThunkName.c_str(), MNG_SHORT_FORM) > 0 && !DemangledThunkName.empty())
		OutThunkName = DemangledThunkName;

	if (DeriveRealNameFromExecThunk(OutThunkName.c_str()).empty())
	{
		msg("[IDAMappingsImporter] '%s' is not an exec thunk (no 'exec' prefix found).\n", OutThunkName.c_str());
		return false;
	}

	return true;
}

inline std::string GetClassNameFromExecThunkName(const qstring& ThunkName)
{
	const std::string ThunkNameStr(ThunkName.c_str());
	const size_t ScopeSep = ThunkNameStr.rfind("::");
	return (ScopeSep != std::string::npos) ? ThunkNameStr.substr(0, ScopeSep) : std::string();
}

inline bool IsIdentifierChar(char C)
{
	return std::isalnum(static_cast<unsigned char>(C)) != 0 || C == '_' || C == ':' || C == '~';
}

using ApplyVTableTypeFn = bool(idaapi*)(vdui_t*, const tinfo_t*);
using ApplyVTableTypeAndNameFn = bool(idaapi*)(vdui_t*, const tinfo_t*, const char*);
using RenameVTableTargetFn = bool(idaapi*)(vdui_t*);
using RenameVTableTargetToFn = bool(idaapi*)(vdui_t*, const char*);

inline void* GetPseudocodeXrefsExport(const char* Name)
{
	void* Export = FindLoadedPluginExport("pseudocode_xrefs", Name);
	if (Export == nullptr)
		Export = FindLoadedPluginExport("IDA-VTable-Utility", Name);

	if (Export == nullptr)
	{
		load_plugin("pseudocode_xrefs");
		Export = FindLoadedPluginExport("pseudocode_xrefs", Name);
	}

	return Export;
}

inline bool ApplyVTableTypeViaPseudocodeXrefs(vdui_t* View, const tinfo_t& FunctionType)
{
	auto* ApplyFn = reinterpret_cast<ApplyVTableTypeFn>(
		GetPseudocodeXrefsExport("pseudocode_xrefs_apply_vtable_type"));
	if (ApplyFn == nullptr)
		return false;

	return ApplyFn(View, &FunctionType);
}

inline bool ApplyVTableTypeViaPseudocodeXrefs(vdui_t* View, const tinfo_t& FunctionType, const std::string* FunctionName)
{
	if (FunctionName != nullptr && !FunctionName->empty())
	{
		auto* ApplyFn = reinterpret_cast<ApplyVTableTypeAndNameFn>(
			GetPseudocodeXrefsExport("pseudocode_xrefs_apply_vtable_type_and_name"));
		if (ApplyFn != nullptr)
			return ApplyFn(View, &FunctionType, FunctionName->c_str());
	}

	return ApplyVTableTypeViaPseudocodeXrefs(View, FunctionType);
}

inline bool RenameVTableTargetViaPseudocodeXrefs(vdui_t* View)
{
	auto* RenameFn = reinterpret_cast<RenameVTableTargetFn>(
		GetPseudocodeXrefsExport("pseudocode_xrefs_rename_vtable_target"));
	return RenameFn != nullptr && RenameFn(View);
}

inline bool RenameVTableTargetViaPseudocodeXrefs(vdui_t* View, const std::string& FunctionName)
{
	auto* RenameFn = reinterpret_cast<RenameVTableTargetToFn>(
		GetPseudocodeXrefsExport("pseudocode_xrefs_rename_vtable_target_to"));
	return RenameFn != nullptr && RenameFn(View, FunctionName.c_str());
}

inline ea_t ResolveFunctionTokenUnderPseudocodeCursor(vdui_t* View)
{
	if (View == nullptr || View->cfunc == nullptr || !View->refresh_cpos(USE_KEYBOARD))
		return BADADDR;

	const strvec_t& Lines = View->cfunc->get_pseudocode();
	if (View->cpos.lnnum < 0 || static_cast<size_t>(View->cpos.lnnum) >= Lines.size())
		return BADADDR;

	qstring PlainLine;
	tag_remove(&PlainLine, Lines[View->cpos.lnnum].line);

	const std::string Plain(PlainLine.c_str());
	if (Plain.empty())
		return BADADDR;

	size_t Cursor = static_cast<size_t>(View->cpos.x);
	if (Cursor >= Plain.size())
		Cursor = Plain.size() - 1;

	if (!IsIdentifierChar(Plain[Cursor]) && Cursor > 0 && IsIdentifierChar(Plain[Cursor - 1]))
		--Cursor;

	if (!IsIdentifierChar(Plain[Cursor]))
		return BADADDR;

	size_t Begin = Cursor;
	while (Begin > 0 && IsIdentifierChar(Plain[Begin - 1]))
		--Begin;

	size_t End = Cursor + 1;
	while (End < Plain.size() && IsIdentifierChar(Plain[End]))
		++End;

	std::string Token = Plain.substr(Begin, End - Begin);
	if (Token.empty())
		return BADADDR;

	const size_t ScopeSep = Token.rfind("::");
	if (ScopeSep != std::string::npos)
		Token = Token.substr(ScopeSep + 2);

	const ea_t TargetAddress = get_name_ea(BADADDR, Token.c_str());
	if (TargetAddress == BADADDR)
		return BADADDR;

	func_t* TargetFunc = get_func(TargetAddress);
	return (TargetFunc != nullptr && TargetFunc->start_ea == TargetAddress) ? TargetAddress : BADADDR;
}

inline ea_t ResolveFunctionUnderCursor(TWidget* Widget)
{
	if (vdui_t* View = get_widget_vdui(Widget))
	{
		const ea_t TokenTarget = ResolveFunctionTokenUnderPseudocodeCursor(View);
		if (TokenTarget != BADADDR)
			return TokenTarget;

		if (View->get_current_item(USE_KEYBOARD) && View->item.citype == VDI_EXPR)
		{
			const cexpr_t* Expr = View->item.e;
			if (Expr != nullptr && Expr->op == cot_call)
				Expr = Expr->x;

			if (Expr != nullptr && Expr->op == cot_obj)
			{
				func_t* TargetFunc = get_func(Expr->obj_ea);
				if (TargetFunc != nullptr && TargetFunc->start_ea == Expr->obj_ea)
					return Expr->obj_ea;
			}
		}

		return BADADDR;
	}

	qstring HighlightedText;
	uint32 HighlightFlags = 0;
	if (get_highlight(&HighlightedText, Widget, &HighlightFlags) && !HighlightedText.empty())
	{
		const ea_t HighlightedAddress = get_name_ea(BADADDR, HighlightedText.c_str());
		if (HighlightedAddress != BADADDR)
		{
			func_t* HighlightedFunc = get_func(HighlightedAddress);
			if (HighlightedFunc != nullptr && HighlightedFunc->start_ea == HighlightedAddress)
				return HighlightedAddress;
		}
	}

	const ea_t CursorEA = get_screen_ea();
	func_t* CursorFunc = get_func(CursorEA);
	if (CursorFunc != nullptr && CursorFunc->start_ea == CursorEA)
		return CursorEA;
	return BADADDR;
}

inline bool IsFunctionCalledFromThunk(ea_t TargetAddress, func_t* ThunkFunction)
{
	if (ThunkFunction == nullptr)
		return false;

	for (ea_t Ref = get_first_cref_to(TargetAddress); Ref != BADADDR; Ref = get_next_cref_to(TargetAddress, Ref))
	{
		if (func_contains(ThunkFunction, Ref))
			return true;
	}

	return false;
}

struct ExecRenameActionHandler : public action_handler_t
{
	int idaapi activate(action_activation_ctx_t* Context) override
	{
		// The symbol under the cursor is the inner sub_XXXX we want to rename
		qstring HighlightedText;
		uint32 HighlightFlags = 0;
		if (!get_highlight(&HighlightedText, Context->widget, &HighlightFlags) || HighlightedText.empty())
		{
			if (vdui_t* CurrentView = get_widget_vdui(Context->widget))
			{
				if (RenameVTableTargetViaPseudocodeXrefs(CurrentView))
					return 1;
			}

			msg("[IDAMappingsImporter] Put the cursor on the inner function call first.\n");
			return 0;
		}

		const ea_t TargetAddress = get_name_ea(BADADDR, HighlightedText.c_str());
		if (TargetAddress == BADADDR)
		{
			msg("[IDAMappingsImporter] '%s' is not a resolvable address.\n", HighlightedText.c_str());
			return 0;
		}

		// The function the cursor sits in should be the exec thunk
		func_t* ThunkFunction = nullptr;
		qstring ThunkName;
		if (!GetCurrentExecThunk(Context->widget, ThunkFunction, ThunkName))
			return 0;

		if (TargetAddress == ThunkFunction->start_ea)
		{
			msg("[IDAMappingsImporter] That's the exec thunk itself, please highlight the inner function call.\n");
			return 0;
		}

		// The rename target must be a real function start (the inner sub), not an arbitrary symbol
		func_t* TargetFunc = get_func(TargetAddress);
		if (TargetFunc == nullptr || TargetFunc->start_ea != TargetAddress)
		{
			msg("[IDAMappingsImporter] '%s' doesn't resolve to a function start, highlight the inner call.\n", HighlightedText.c_str());
			return 0;
		}

		// And it must actually be called from inside this exec thunk and not just any function whose name happens to be highlighted while the cursor is in the thunk
		if (!IsFunctionCalledFromThunk(TargetAddress, ThunkFunction))
		{
			msg("[IDAMappingsImporter] '%s' isn't called from this exec thunk, highlight the inner call.\n", HighlightedText.c_str());
			return 0;
		}

		std::string RealName = DeriveRealNameFromExecThunk(ThunkName.c_str());

		// Look up the signature first: it both cleans the name and supplies the prototype
		auto& Signatures = CurrentIdbSignatures();
		const auto SignatureIt = Signatures.find(ThunkFunction->start_ea);
		const std::string SignatureReturnType =
			(SignatureIt != Signatures.end() && SignatureIt->second.bHasFallbackSignature)
			? SignatureIt->second.FallbackSignature.ReturnType
			: std::string();

		const std::string* CppUnmangledName =
			(SignatureIt != Signatures.end())
			? GetRegisteredExecCppUnmangledName(SignatureIt->second, GHasCppSDKTypes)
			: nullptr;

		if (CppUnmangledName != nullptr)
			RealName = *CppUnmangledName;
		else
			RealName = StripReturnTypeSuffix(RealName, SignatureReturnType);

		if (set_name(TargetAddress, RealName.c_str(), SN_FORCE | SN_NOCHECK | SN_NOWARN))
			msg("[IDAMappingsImporter] 0x%llX -> %s\n", static_cast<uint64>(TargetAddress), RealName.c_str());
		else
			msg("[IDAMappingsImporter] Failed to rename 0x%llX to %s\n", static_cast<uint64>(TargetAddress), RealName.c_str());

		// Apply the real prototype if the import recorded a signature for this thunk
		if (SignatureIt != Signatures.end())
		{
			if (ApplyRegisteredExecSignature(TargetAddress, GetClassNameFromExecThunkName(ThunkName), SignatureIt->second, GHasCppSDKTypes))
				msg("[IDAMappingsImporter]   prototype applied.\n");
		}

		// Redecompile the current view so the rename + prototype show without a manual F5
		if (init_hexrays_plugin())
		{
			mark_cfunc_dirty(TargetAddress, false);

			if (vdui_t* CurrentView = get_widget_vdui(Context->widget))
				CurrentView->refresh_view(true);
		}

		return 1;
	}

	action_state_t idaapi update(action_update_ctx_t* Context) override
	{
		const int WidgetType = Context->widget_type;
		return (WidgetType == BWN_DISASM || WidgetType == BWN_PSEUDOCODE) ? AST_ENABLE_FOR_WIDGET : AST_DISABLE_FOR_WIDGET;
	}
};

struct ExecApplySignatureActionHandler : public action_handler_t
{
	int idaapi activate(action_activation_ctx_t* Context) override
	{
		msg("[IDAMappingsImporter] %s\n", ExecApplySignatureActionName);

		func_t* ThunkFunction = nullptr;
		qstring ThunkName;
		if (!GetCurrentExecThunk(Context->widget, ThunkFunction, ThunkName))
			return 0;

		auto& Signatures = CurrentIdbSignatures();
		const auto SignatureIt = Signatures.find(ThunkFunction->start_ea);
		if (SignatureIt == Signatures.end())
		{
			msg("[IDAMappingsImporter] No signature registered for exec thunk 0x%llX.\n", static_cast<uint64>(ThunkFunction->start_ea));
			return 0;
		}

		const std::string ClassName = GetClassNameFromExecThunkName(ThunkName);
		const std::string* CppUnmangledName = GetRegisteredExecCppUnmangledName(SignatureIt->second, GHasCppSDKTypes);
		tinfo_t FunctionType;
		if (!MakeRegisteredExecSignatureType(&FunctionType, ClassName, SignatureIt->second, GHasCppSDKTypes))
		{
			msg("[IDAMappingsImporter] Failed to build registered prototype for exec thunk 0x%llX.\n", static_cast<uint64>(ThunkFunction->start_ea));
			return 0;
		}

		const std::string SignatureText = DescribeRegisteredExecSignature(ClassName, SignatureIt->second, GHasCppSDKTypes);
		msg(
			"[IDAMappingsImporter] Applying %s signature: %s\n",
			IsRegisteredExecCppSignatureSelected(SignatureIt->second, GHasCppSDKTypes) ? "CppTypeSignature" : "FallbackCppSignatureInfo",
			SignatureText.c_str());

		if (vdui_t* CurrentView = get_widget_vdui(Context->widget))
		{
			msg(
				"[IDAMappingsImporter] Apply target=vtable name=%s type=%s\n",
				CppUnmangledName != nullptr ? CppUnmangledName->c_str() : "<none>",
				SignatureText.c_str());

			if (ApplyVTableTypeViaPseudocodeXrefs(CurrentView, FunctionType, CppUnmangledName))
			{
				msg("[IDAMappingsImporter] SET SIGNATURE via IDA-VTable-Utility: %s\n", SignatureText.c_str());
				msg("[IDAMappingsImporter] Applied prototype through IDA-VTable-Utility.\n");
				return 1;
			}
		}

		const ea_t TargetAddress = ResolveFunctionUnderCursor(Context->widget);
		if (TargetAddress == BADADDR)
		{
			msg("[IDAMappingsImporter] Cursor is not on a function.\n");
			return 0;
		}

		if (TargetAddress == ThunkFunction->start_ea)
		{
			msg("[IDAMappingsImporter] That's the exec thunk itself, put the cursor on the wrapped function.\n");
			return 0;
		}

		if (!IsFunctionCalledFromThunk(TargetAddress, ThunkFunction))
		{
			msg("[IDAMappingsImporter] Function 0x%llX is not called from this exec thunk.\n", static_cast<uint64>(TargetAddress));
			return 0;
		}

		msg(
			"[IDAMappingsImporter] Apply target=normal address=0x%llX name=%s type=%s\n",
			static_cast<uint64>(TargetAddress),
			CppUnmangledName != nullptr ? CppUnmangledName->c_str() : "<none>",
			SignatureText.c_str());

		if (apply_tinfo(TargetAddress, FunctionType, TINFO_DEFINITE))
		{
			msg("[IDAMappingsImporter] SET SIGNATURE at 0x%llX: %s\n", static_cast<uint64>(TargetAddress), SignatureText.c_str());
			msg("[IDAMappingsImporter] Applied prototype to 0x%llX.\n", static_cast<uint64>(TargetAddress));

			if (CppUnmangledName != nullptr
				&& set_name(TargetAddress, CppUnmangledName->c_str(), SN_FORCE | SN_NOCHECK | SN_NOWARN))
			{
				msg("[IDAMappingsImporter] Renamed 0x%llX -> %s.\n", static_cast<uint64>(TargetAddress), CppUnmangledName->c_str());
			}
		}
		else
			msg("[IDAMappingsImporter] Failed to apply prototype to 0x%llX.\n", static_cast<uint64>(TargetAddress));

		if (init_hexrays_plugin())
		{
			mark_cfunc_dirty(TargetAddress, false);

			if (vdui_t* CurrentView = get_widget_vdui(Context->widget))
				CurrentView->refresh_view(true);
		}

		return 1;
	}

	action_state_t idaapi update(action_update_ctx_t* Context) override
	{
		const int WidgetType = Context->widget_type;
		return (WidgetType == BWN_DISASM || WidgetType == BWN_PSEUDOCODE) ? AST_ENABLE_FOR_WIDGET : AST_DISABLE_FOR_WIDGET;
	}
};

struct ExecRenameUiListener : public event_listener_t
{
	ssize_t idaapi on_event(ssize_t NotificationCode, va_list Arguments) override
	{
		if (NotificationCode == ui_finish_populating_widget_popup)
		{
			TWidget* Widget   = va_arg(Arguments, TWidget*);
			TPopupMenu* Popup = va_arg(Arguments, TPopupMenu*);

			const int WidgetType = get_widget_type(Widget);
			if (WidgetType == BWN_DISASM || WidgetType == BWN_PSEUDOCODE)
			{
				attach_action_to_popup(Widget, Popup, ExecRenameActionName);
				attach_action_to_popup(Widget, Popup, ExecApplySignatureActionName);
			}
		}
		return 0;
	}
};

inline ExecRenameActionHandler*         GExecRenameHandler = nullptr;
inline ExecApplySignatureActionHandler* GExecApplySignatureHandler = nullptr;
inline ExecRenameUiListener             GExecRenameListener;
inline int                              GExecRenameRefCount = 0;

inline void InstallExecRenameAction()
{
	if (GExecRenameRefCount++ > 0)
		return;

	GExecRenameHandler = new ExecRenameActionHandler();
	GExecApplySignatureHandler = new ExecApplySignatureActionHandler();

	const action_desc_t Desc = ACTION_DESC_LITERAL_OWNER(
		ExecRenameActionName,
		"Rename UE exec target function",
		GExecRenameHandler,
		nullptr,        // no plugmod owner: the action is process-wide
		"Alt-U",
		"Rename the highlighted sub_XXXX to the real UE function (from the enclosing exec thunk)",
		-1,
		ADF_GLOBAL);

	register_action(Desc);

	const action_desc_t ApplySignatureDesc = ACTION_DESC_LITERAL_OWNER(
		ExecApplySignatureActionName,
		"Apply UE exec target function signature",
		GExecApplySignatureHandler,
		nullptr,        // no plugmod owner: the action is process-wide
		"Ctrl+Alt+Q",
		"Apply the enclosing UE exec thunk signature to the function under the cursor",
		-1,
		ADF_GLOBAL);

	register_action(ApplySignatureDesc);

	hook_event_listener(HT_UI, &GExecRenameListener, nullptr);
}

inline void UninstallExecRenameAction()
{
	if (GExecRenameRefCount <= 0 || --GExecRenameRefCount > 0)
		return;

	unhook_event_listener(HT_UI, &GExecRenameListener);
	unregister_action(ExecApplySignatureActionName);
	unregister_action(ExecRenameActionName);
	GExecApplySignatureHandler = nullptr;
	GExecRenameHandler = nullptr;
}
