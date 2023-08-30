#pragma once
#include <ida.hpp>
#include <pro.h>

template<typename char_type>
class ida_string_base
{
private:
	static constexpr int char_size = sizeof(char_type);

	static constexpr uintptr_t use_allocated_buffer_mask = 0x8000000000000000;

private:
	union
	{
		struct
		{
			char_type* buffer_start;
			char_type* buffer_end;
		};

		unsigned char inline_buffer[0xF];
		unsigned char inline_length_inverse : 4;
		unsigned char reserved : 3;
		unsigned char use_allocated_buffer : 1;
	};

public:
	ida_string_base()
		: buffer_start(nullptr)
		, buffer_end(nullptr)
	{
		mark_as_allocated();
	}

	ida_string_base(const char_type* str, bool take_ownership = false)
		: buffer_start(nullptr)
		, buffer_end(nullptr)
	{
		if (!str)
			return;

		//int length = ida_string_base::strlen(str);
		int length = qstrlen(str);

		if (take_ownership)
		{
			takeover_outline_string(str, length);
			return;
		}

		if (is_length_suitable_for_inline(length))
		{
			place_string_inline(str, length);
			return;
		}

		allocate_outline_string(str, length);
	}

	ida_string_base(ida_string_base&& other)
		: buffer_start(other.buffer_start)
		, buffer_end(other.buffer_end)
	{
		other.buffer_start = nullptr;
		other.buffer_end = nullptr;
	}

	ida_string_base(const ida_string_base& other)
		: buffer_start(nullptr)
		, buffer_end(nullptr)
	{
		if (other.is_inline_string())
		{
			memcpy(*this, &other, sizeof(ida_string_base));
			return;
		}

		allocate_outline_string(other, other.length());
	}

	~ida_string_base()
	{
		cleanup_self();
	}

public:
	ida_string_base& operator=(const char* string)
	{
		cleanup_self();

		int length = qstrlen(string);

		if (is_length_suitable_for_inline(length))
		{
			place_string_inline(string, length);
			return *this;
		}

		allocate_outline_string(string, length);

		return *this;
	}

	ida_string_base& operator=(ida_string_base&& other)
	{
		cleanup_self();

		memcpy(this, &other, sizeof(ida_string_base));
		memset(&other, 0, sizeof(ida_string_base));

		return *this;
	}

	ida_string_base& operator=(const ida_string_base& other)
	{
		cleanup_self();

		if (other.is_inline_string())
		{
			memcpy(*this, &other, sizeof(ida_string_base));
			return;
		}

		return *this;
	}

private:
	void place_string_inline(const char_type* string, int len)
	{
		memset(this, 0, sizeof(ida_string_base));
		inline_length_inverse = 0x10 - len;
		use_allocated_buffer = false;
		memcpy(inline_buffer, string, len * char_size);
	}

	void fit_outline_buffer(int len)
	{
		int length_with_null_terminator = len + 1;
	
		buffer_start = reinterpret_cast<char_type*>((is_empty() || is_inline_string()) ? qalloc(length_with_null_terminator) : qrealloc(buffer_start, length_with_null_terminator));

		buffer_end = buffer_start + length_with_null_terminator;
		buffer_start[len] = 0;
		mark_as_allocated();
	}

	void allocate_outline_string(const char_type* string, int len)
	{
		fit_outline_buffer(len);

		memcpy(buffer_start, string, len * char_size);
	}

	void takeover_outline_string(const char_type* string, int len)
	{
		int length_with_null_terminator = len + 1;
		
		buffer_start = const_cast<char_type*>(string);
		buffer_end = const_cast<char_type*>(string + length_with_null_terminator);
		mark_as_allocated();
	}

	void cleanup_self()
	{
		if (is_inline_string())
			return;

		qfree(buffer_start);
		memset(this, 0, sizeof(ida_string_base));
	}

private:
	static int strlen(const char_type* str)
	{
		int len = 0;
		while (str[len] != 0)
			len++;

		return len;
	}

private:
	void mark_as_allocated()
	{
		buffer_end = reinterpret_cast<char_type*>(reinterpret_cast<uintptr_t>(buffer_end) | use_allocated_buffer_mask);
	}

	bool is_length_suitable_for_inline(int len) const
	{
		return (len * char_size) < 0x10;
	}

	bool is_inline_string() const
	{
		return !(reinterpret_cast<uintptr_t>(buffer_end) & use_allocated_buffer_mask);
	}

	int get_inline_length_bytes() const
	{
		return 0x10 - inline_length_inverse;
	}

	inline const char_type* get_buffer_start() const
	{
		return buffer_start;
	}

	inline const char_type* get_buffer_end() const
	{
		return reinterpret_cast<char_type*>(reinterpret_cast<uintptr_t>(buffer_end) & ~use_allocated_buffer_mask);
	}

	int length_bytes() const
	{
		if (is_inline_string())
			return get_inline_length_bytes();

		return reinterpret_cast<uintptr_t>(get_buffer_start()) - reinterpret_cast<uintptr_t>(get_buffer_end());
	}

public:
	inline bool operator==(const ida_string_base& other) const
	{
		return length() == other.length() && (qstrcmp(c_str(), other.c_str()) == 0);
	}

	inline bool operator!=(const ida_string_base& other) const
	{
		return length() != other.length() || (qstrcmp(c_str(), other.c_str()) != 0);
	}

	operator const char_type* () const
	{
		return c_str();
	}

public:
	int length() const
	{
		if (length_bytes() <= 0)
			return 0;

		return length_bytes() - 1;
	}

	bool is_empty() const
	{
		return length() == 0;
	}

	const char_type* c_str() const
	{
		if (is_inline_string())
			return reinterpret_cast<const char_type*>(inline_buffer);

		return buffer_start;
	}

	char* buffer(int required_buffer_size)
	{
		if (length() < required_buffer_size)
			fit_outline_buffer(required_buffer_size);

		return const_cast<char_type*>(c_str());
	}
};

using ida_string = ida_string_base<char>;
using ida_wstring = ida_string_base<wchar_t>;