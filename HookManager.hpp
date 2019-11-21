#pragma once

enum HOOK_TYPE
{
	JMP,
	CALL,
	MOV_EAX,
};

class CHookManager
{
private:
	PBYTE _Address = nullptr;
	PBYTE _HookAddress = nullptr;
	PVOID _Original = nullptr;
	HOOK_TYPE _Type;

	BYTE* _OrgBytes = nullptr;

	int _HookLenght = 0;

private:
	//https://www.unknowncheats.me/forum/868662-post1.html
	PVOID SetDetours(BYTE *pbTargetFunction, const BYTE *pbDetourFunction, INT len)
	{
		DWORD dwProtect;
		PBYTE pbDetour = (PBYTE)malloc(len + 5);

		VirtualProtect(pbTargetFunction, len, PAGE_EXECUTE_READWRITE, &dwProtect);
		memcpy(pbDetour, pbTargetFunction, len);
		pbDetour += len;

		*(BYTE *)(pbDetour + 0) = 0xE9;
		*(DWORD *)(pbDetour + 1) = (DWORD)(pbTargetFunction + len - pbDetour) - 5;

		int i = 0;

		switch (_Type)
		{
		case JMP:
			*(BYTE *)(pbTargetFunction + 0) = 0xE9;
			*(DWORD *)(pbTargetFunction + 1) = (DWORD)(pbDetourFunction - pbTargetFunction) - 5;
			i = 5;
			break;

		case CALL:
			*(BYTE *)(pbTargetFunction + 0) = 0xE8;
			*(DWORD *)(pbTargetFunction + 1) = (DWORD)(pbDetourFunction - pbTargetFunction) - 5;
			i = 5;
			break;

		case MOV_EAX:
			*(BYTE *)(pbTargetFunction + 0) = 0xB8;
			*(DWORD *)(pbTargetFunction + 1) = (DWORD)(pbDetourFunction);
			*(WORD *)(pbTargetFunction + 5) = 0xE0FF;
			i = 7;
			break;
		}

		for (; i < len; ++i)
			*(BYTE *)(pbTargetFunction + i) = 0x90;

		VirtualProtect(pbTargetFunction, len, dwProtect, &dwProtect);

		return (pbDetour - len);
	}

public:
	CHookManager() = default;
	CHookManager(PBYTE Address, HOOK_TYPE Type)
	{
		_Address = Address;
		_Type = Type;
	}

	~CHookManager()
	{
		if (_OrgBytes)
			delete[] _OrgBytes;
	}

	static CHookManager& instance()
	{
		static CHookManager i;
		return i;
	}
	 
	inline auto InlineJump(BYTE *pbTargetFunction, const BYTE *pbDetourFunction, INT len = 5) noexcept
	{
		_Type = JMP;
		return SetDetours(pbTargetFunction, pbDetourFunction, len);
	}

	inline auto InlineCall(BYTE *pbTargetFunction, const BYTE *pbDetourFunction, INT len = 5) noexcept
	{
		_Type = CALL;
		return SetDetours(pbTargetFunction, pbDetourFunction, len);
	}

	bool Setup(PBYTE NewLocation, const int len = 5) noexcept
	{
		_HookLenght = len;
		_HookAddress = NewLocation;

		_OrgBytes = new BYTE[_HookLenght];
		std::memcpy(_OrgBytes, _Address, _HookLenght);

		return (_Original = SetDetours(_Address, NewLocation, len)) != nullptr;
	}

	inline void UnHook() noexcept
	{
		DWORD dwBack = NULL;
		if (VirtualProtect(_Original, _HookLenght, PAGE_EXECUTE_READWRITE, &dwBack))
		{
			std::memcpy(_Original, _OrgBytes, _HookLenght);
			VirtualProtect(_Original, _HookLenght, dwBack, &dwBack);
		}
	}

	template< typename T >
	T GetOriginal() noexcept
	{
		return reinterpret_cast<T>(_Original);
	}
};
