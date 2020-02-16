#pragma once

#include "env.h"
#include <Windows.h>

class Monitor
{
public:
	inline Monitor()
		: _cs{ 0 } {
		InitializeCriticalSection(&_cs);
	}
	inline ~Monitor() {
		DeleteCriticalSection(&_cs);
	}

public:
	inline void								Enter() {
		EnterCriticalSection(&_cs);
	}
	inline void								Exit() {
		LeaveCriticalSection(&_cs);
	}

private:
	CRITICAL_SECTION						_cs;
};

class MonitorScope
{
public:
	inline MonitorScope(Monitor& monitor) {
		_m.Enter();
	}
	inline ~MonitorScope() {
		_m.Exit();
	}

private:
	Monitor									_m;
};