#pragma once

#include <string>

#pragma pack(push, 1)

class Guid // #include <uuid/uuid.h>
{
public:
	Guid();
    Guid(const std::string& s);
    Guid(unsigned char* buffer, int length);

public:
	enum ToStringFormat
	{
		TOSTRINGFORMAT_D,
		TOSTRINGFORMAT_N,
		TOSTRINGFORMAT_B,
		TOSTRINGFORMAT_P,
		TOSTRINGFORMAT_X
	};
    inline std::string                  ToString()
    {
        return ToString(TOSTRINGFORMAT_D);
    }
	std::string				            ToString(ToStringFormat fmt);
    void                                Clear();
    inline unsigned char*               ToArray()
    {
        return (unsigned char*)(void*)this;
    }
    inline std::string                  AsMemoryBytes()
    {
        unsigned char* buffer = this->ToArray();
        return std::string((char*)buffer, sizeof(Guid));
    }

public:
    static Guid				            NewGuid();
    static Guid				            NewGuid(uint64_t x, uint64_t y);
    static Guid&                        Empty();
    static Guid                         ParseExact(const std::string& s);
    static Guid&                        ParseExact(Guid& guid, const std::string& s);

public:
    template<typename TValue>
    static TValue                       HexToNumber(unsigned char*& stream_ptr, unsigned char* endoff_ptr)
    {
        TValue nu = 0;
        if (stream_ptr >= endoff_ptr)
        {
            return nu;
        }

        int x = (1 << 1) * sizeof(TValue);
        for (int c = 0; c < x; )
        {
            unsigned char ch = *stream_ptr++;
            if (ch == '-' || ch == '{' || ch == '}' || ch == ',' || ch == '(' || ch == ')')
            {
                if (stream_ptr >= endoff_ptr)
                {
                    break;
                }
                else
                {
                    continue;
                }
            }

            if (ch >= '0' && ch <= '9')
            {
                nu = nu << (c ? 4 : 0) | (TValue)(ch - '0');
            }
            else if (ch >= 'a' && ch <= 'f')
            {
                nu = nu << (c ? 4 : 0) | (TValue)(10 + (ch - 'a'));
            }
            else if (ch >= 'A' && ch <= 'F')
            {
                nu = nu << (c ? 4 : 0) | (TValue)(10 + (ch - 'A'));
            }
            else
            {
                break;
            }

            c++;
        }
        return nu;
    }
    bool                                operator==(const Guid& guid);
    inline bool                         operator!=(const Guid& guid)
    {
        Guid& right = const_cast<Guid&>(guid);
        Guid& left = *this;
        return right == left;
    }

public:
    union
    {
        struct
        {
            unsigned int			    Data1;
            unsigned short			    Data2;
            unsigned short			    Data3;
            unsigned char		        Data4[8];
        };
        struct
        {
            signed int                  _a;
            signed short                _b;
            signed short                _c;
            unsigned char               _d;
            unsigned char               _e;
            unsigned char               _f;
            unsigned char               _g;
            unsigned char               _h;
            unsigned char               _i;
            unsigned char               _j;
            unsigned char               _k;
        };
    };
};

#pragma pack(pop)