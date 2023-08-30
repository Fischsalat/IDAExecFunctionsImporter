#include <Windows.h>
#include <ida.hpp>
#include <idp.hpp>
#include <loader.hpp>
#include <bytes.hpp>

#include <fpro.h>
#include <name.hpp>
#include <diskio.hpp>
#include <kernwin.hpp>

#include "ida_file.h"
#include "ida_string.h"

size_t get_real_imagebase()
{
	return getinf(INF_IMAGEBASE);
}

struct plugin_ctx_t : public plugmod_t
{
	virtual bool idaapi run(size_t) override
	{
		ida_string result = ask_file(false, "*.idmap", "Load the file, or %s", "die!");
		
		const char* reselult = result.c_str();

		msg("Selected result.c_str(): %s\n", result.c_str());

		ida_file selected_file(result, ida_file::open_mode::binary_read_only);

		auto image_base = get_real_imagebase();
		msg("Imagebase: 0x%llX\n", image_base);
		msg("Imagebase: 0x%llX\n", get_real_imagebase());

		hook_type_t processor_hook = HT_IDP;

		if (selected_file.is_open())
		{
			while (selected_file.can_read_more())
			{
				uint32 offset = selected_file.read<uint32>();
				uint16 name_len = selected_file.read<uint16>();

				ida_string name_string = selected_file.read_string(name_len);

				set_name(image_base + offset, name_string.c_str());

				//msg("offset: 0x%X\n", offset);
				//msg("name_len: 0x%X\n", name_len);
				//msg("name_string: %s\n", name_string.c_str());
			}
		}

		return true;
	}
};


//--------------------------------------------------------------------------
static plugmod_t* idaapi init()
{
	return new plugin_ctx_t;
}

//--------------------------------------------------------------------------
plugin_t PLUGIN =
{
  IDP_INTERFACE_VERSION,
  PLUGIN_UNL            // Unload the plugin immediately after calling 'run'
  | PLUGIN_MULTI,       // The plugin can work with multiple idbs in parallel
  init,                 // initialize
  nullptr,
  nullptr,
  nullptr,              // long comment about the plugin
  nullptr,              // multiline help about the plugin
  "IDAExecFunctionsImporter", // the preferred short name of the plugin
  "Ctrl-Alt-A",         // the preferred hotkey to run the plugin
};