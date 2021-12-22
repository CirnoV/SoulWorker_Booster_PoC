#include <Windows.h>
#include "MinHook.h"

size_t read_uint8888_le_addr = 0;
size_t read_uint88_le_addr = 0;
size_t v_disk_file_in_stream_read_addr = 0;

typedef size_t(__thiscall* v_disk_file_in_stream_read_t)(void*, void*, size_t);

v_disk_file_in_stream_read_t builtin_v_disk_file_in_stream_read = 0;

__declspec(naked) void read_uint16_le_hook()
{
    {__asm {
        push ecx
        mov ecx, [edi + 0x20]
        mov edx, [edi + 4]
        push ebx
        mov ebx, [esp + 8 + 4]
        push ebp
        push esi
        push 2
        lea eax, [esp + 0x14 - 2]
        push eax
        push ebx
        push ecx
        xor esi, esi
        call edx
        add esp, 0x10
        cmp eax, 2
        jnz error
        movzx esi, word ptr ss:[esp + 0x10 - 2]
        mov ecx, [esp + 0x10 + 8]
        xor eax, eax
        mov[ecx], esi

    end:
        pop esi
        pop ebp
        pop ebx
        pop ecx
        retn

    error:
        mov eax, 0xFFFFFFFF
        mov[ecx], 0
        jmp end
    }}
}

__declspec(naked) void read_uint32_le_hook()
{
    {__asm {
        push ecx
        mov ecx, [esi + 0x20]
        mov edx, [esi + 4]
        push ebx
        mov ebx, [esp + 8 + 4]
        push ebp
        push edi
        push 4
        lea eax, [esp + 0x14 - 4]
        push eax
        push ebx
        push ecx
        xor edi, edi
        call edx
        add esp, 0x10
        cmp eax, 4
        jnz error
        mov edi, [esp + 0x10 - 4]
        mov ecx, [esp + 0x10 + 8]
        xor eax, eax
        mov[ecx], edi

    end:
        pop edi
        pop ebp
        pop ebx
        pop ecx
        retn

    error:
        mov eax, 0xFFFFFFFF
        mov ecx, [esp + 0x10 + 8]
        mov[ecx], 0
        jmp end
    }}
}

size_t __fastcall v_disk_file_in_stream_read_cache(void* _this, void* unused, void* buffer, size_t size)
{
    static char cache[0xFF] = {};
    static size_t cursor = NULL;
    static size_t cache_size = NULL;

    if (size != 2 && size != 4)
    {
        return builtin_v_disk_file_in_stream_read(_this, buffer, size);
    }

    if (cursor < cache_size) {
        memcpy(buffer, (char*)(cache + cursor), size);
        cursor += size;
        if (cursor >= cache_size) {
            cache_size = NULL;
            cursor = NULL;
        }
        return size;
    }

    size_t result = builtin_v_disk_file_in_stream_read(_this, buffer, size);
    if (size == 4)
    {
        switch (*(unsigned __int32*)buffer)
        {
        // Local file header
        case 0x04034B50:
        case 0x51561E05:
            cache_size = 26;
            break;

        // Central directory file header
        case 0x02014B50:
        case 0x57541E05:
            cache_size = 42;
            break;

        // EOCD
        case 0x06054B50:
        case 0x53501E05:
            cache_size = 18;
            break;

        default:
            return result;
        }
        builtin_v_disk_file_in_stream_read(_this, cache, cache_size);
        cursor = 0;
    }

    return result;
}

void start()
{
    size_t base_addr = (size_t)GetModuleHandleA("Base.dll");

    read_uint8888_le_addr = base_addr + 0x0002FFB0;
    read_uint88_le_addr = base_addr + 0x0002FF10;
    v_disk_file_in_stream_read_addr = base_addr + 0x0006A000;

    MH_Initialize();

    // Patch 1: 바이너리 읽기 성능 개선
    MH_CreateHook((LPVOID)read_uint8888_le_addr, &read_uint32_le_hook, NULL);
    MH_CreateHook((LPVOID)read_uint88_le_addr, &read_uint16_le_hook, NULL);
    MH_EnableHook((LPVOID)read_uint8888_le_addr);
    MH_EnableHook((LPVOID)read_uint88_le_addr);

    // Patch 2: zip 헤더 캐시
    MH_CreateHook((LPVOID)v_disk_file_in_stream_read_addr, &v_disk_file_in_stream_read_cache, (LPVOID*)&builtin_v_disk_file_in_stream_read);
    MH_EnableHook((LPVOID)v_disk_file_in_stream_read_addr);
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReversed)
{
    switch (fdwReason)
    {
    case DLL_PROCESS_ATTACH:
        start();
        break;
    case DLL_PROCESS_DETACH:
        // MH_Uninitialize();
        break;
    }
    return TRUE;
}
