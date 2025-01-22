#pragma once
#include <fpro.h>
#include <diskio.hpp>

#include "ida_string.h"

class ida_file
{
public:
	enum class open_mode
	{
		none,
		read_only,
		binary_read_only,
		read_write,
		binary_read_write,
	};

private:
	FILE* file;
	open_mode mode;
	int pos;
	int size;

public:
	ida_file()
		: file(nullptr)
		, mode(open_mode::none)
		, pos(0)
		, size(0)
	{
	}

	ida_file(const char* file_path, open_mode new_mode = open_mode::read_only)
		: file(nullptr)
		, mode(new_mode)
		, pos(0)
		, size(0)
	{
		if (!file_path)
			return;

		if (open_file(file_path, new_mode))
		{
			qfseek(file, 0, SEEK_END);
			size = qftell(file);
			qfseek(file, 0, SEEK_SET);
		}
	}

	~ida_file()
	{
		close_file();
	}

public:
	bool is_open()
	{
		return file && mode != open_mode::none;
	}

	bool can_write()
	{
		return is_open() && (mode >= open_mode::read_write);
	}

	bool open_file(const char* file_name, open_mode new_mode = open_mode::read_only)
	{
		if (is_open())
			close_file();

		mode = new_mode;

		switch (mode)
		{
		case open_mode::read_only:
			file = fopenRT(file_name);
			break;
		case open_mode::binary_read_only:
			file = fopenRB(file_name);
			break;
		case open_mode::read_write:
			file = fopenWT(file_name);
			break;
		case open_mode::binary_read_write:
			file = fopenWB(file_name);
			break;
		default:
			break;
		}

		return file != nullptr;
	}

	void close_file()
	{
		qfclose(file);
		file = nullptr;
		mode = open_mode::none;
		pos = 0;
	}

public:
	template<typename T>
	void read(T& out_value)
	{
		pos += sizeof(T);
		qfread(file, &out_value, sizeof(T));
	}

	template<typename T>
	T read()
	{
		T ret_value;
		pos += sizeof(T);

		qfread(file, &ret_value, sizeof(T));

		return ret_value;
	}

	ida_string read_string(int length)
	{
		ida_string ret;
		pos += length;

		qfread(file, ret.buffer(length), length);

		return ret;
	}

	bool can_read_more()
	{
		return pos < size;
	}
};
