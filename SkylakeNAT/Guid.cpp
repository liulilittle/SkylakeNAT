#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <time.h>
#include <limits>
#include <limits.h>

#include "Guid.h"

#ifdef WIN32
#include <objbase.h>
#else
#include <uuid/uuid.h>
#endif

std::string Guid::ToString(ToStringFormat fmt)
{
	Guid& guid = *this;
	char buf[255];
	buf[0] = '\x0';
	if (fmt == TOSTRINGFORMAT_N)
	{
		snprintf(
			buf,
			sizeof(buf),
			"%08x%04x%04x%02x%02x%02x%02x%02x%02x%02x%02x",
			(uint32_t)guid.Data1, (uint32_t)guid.Data2, (uint32_t)guid.Data3,
			(uint32_t)guid.Data4[0], (uint32_t)guid.Data4[1],
			(uint32_t)guid.Data4[2], (uint32_t)guid.Data4[3],
			(uint32_t)guid.Data4[4], (uint32_t)guid.Data4[5],
			(uint32_t)guid.Data4[6], (uint32_t)guid.Data4[7]);
	}
	else if (fmt == TOSTRINGFORMAT_B)
	{
		snprintf(
			buf,
			sizeof(buf),
			"{%08x-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x}",
			(uint32_t)guid.Data1, (uint32_t)guid.Data2, (uint32_t)guid.Data3,
			(uint32_t)guid.Data4[0], (uint32_t)guid.Data4[1],
			(uint32_t)guid.Data4[2], (uint32_t)guid.Data4[3],
			(uint32_t)guid.Data4[4], (uint32_t)guid.Data4[5],
			(uint32_t)guid.Data4[6], (uint32_t)guid.Data4[7]);
	}
	else if (fmt == TOSTRINGFORMAT_P)
	{
		snprintf(
			buf,
			sizeof(buf),
			"(%08x-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x)",
			(uint32_t)guid.Data1, (uint32_t)guid.Data2, (uint32_t)guid.Data3,
			(uint32_t)guid.Data4[0], (uint32_t)guid.Data4[1],
			(uint32_t)guid.Data4[2], (uint32_t)guid.Data4[3],
			(uint32_t)guid.Data4[4], (uint32_t)guid.Data4[5],
			(uint32_t)guid.Data4[6], (uint32_t)guid.Data4[7]);
	}
	else if (fmt == TOSTRINGFORMAT_X)
	{
		snprintf(
			buf,
			sizeof(buf),
			"{0x%08x,0x%04x,0x%04x,{0x%2x,0x%2x,0x%2x,0x%2x,0x%2x,0x%2x,0x%2x,0x%2x}}",
			(uint32_t)guid.Data1, (uint32_t)guid.Data2, (uint32_t)guid.Data3,
			(uint32_t)guid.Data4[0], (uint32_t)guid.Data4[1],
			(uint32_t)guid.Data4[2], (uint32_t)guid.Data4[3],
			(uint32_t)guid.Data4[4], (uint32_t)guid.Data4[5],
			(uint32_t)guid.Data4[6], (uint32_t)guid.Data4[7]);
	}
	else
	{
		snprintf(
			buf,
			sizeof(buf),
			"%08x-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x",
			(uint32_t)guid.Data1, (uint32_t)guid.Data2, (uint32_t)guid.Data3,
			(uint32_t)guid.Data4[0], (uint32_t)guid.Data4[1],
			(uint32_t)guid.Data4[2], (uint32_t)guid.Data4[3],
			(uint32_t)guid.Data4[4], (uint32_t)guid.Data4[5],
			(uint32_t)guid.Data4[6], (uint32_t)guid.Data4[7]);
	}
	return std::string(buf);
}

Guid::Guid()
{
    Clear();
}

Guid::Guid(const std::string& s)
{
    Clear();
    ParseExact(*this, s);
}

Guid::Guid(unsigned char* buffer, int length)
{
    Clear();
    if (length > 0 && NULL != buffer)
    {
		int guid_sizeof = sizeof(Guid);
        if (length > guid_sizeof)
        {
            length = guid_sizeof;
        }
        memcpy(this, buffer, length);
    }
}

Guid Guid::NewGuid()
{
    Guid guid;
#ifdef WIN32
    CoCreateGuid((GUID*)&guid);
#else
    uuid_generate(*(uuid_t*)&guid); // uuid_unparse(uuid, szuuid);
#endif
    return guid;
}

Guid Guid::NewGuid(uint64_t x, uint64_t y)
{
    Guid guid;
    uint64_t* pBuf = (uint64_t*)&guid;
    pBuf[0] = x;
    pBuf[1] = y;
    return guid;
}

Guid& Guid::Empty()
{
    static Guid defaultGUID;
    return defaultGUID;
}

Guid Guid::ParseExact(const std::string& s)
{
    Guid guid;
    return ParseExact(guid, s);
}

Guid& Guid::ParseExact(Guid& guid, const std::string& s)
{
    guid = Guid::Empty();
    if (s.empty())
    {
        return guid;
    }

    size_t length = s.size();
    unsigned char* stream_ptr = (unsigned char*)s.data();
    unsigned char* endoff_ptr = stream_ptr + length;

    guid.Data1 = HexToNumber<int>(stream_ptr, endoff_ptr);
    guid.Data2 = HexToNumber<short>(stream_ptr, endoff_ptr);
    guid.Data3 = HexToNumber<short>(stream_ptr, endoff_ptr);
    for (int i = 0, l = sizeof(guid.Data4); i < l; i++)
    {
        guid.Data4[i] = HexToNumber<unsigned char>(stream_ptr, endoff_ptr);
    }
    return guid;
}

bool Guid::operator==(const Guid& guid)
{
    return 0 == memcmp(this, &guid, sizeof(guid));
}
