# POC-RunPE

POC Fonctionnel sur W10 et W7 avec des applications 32bits.<br>
/!\ Sur W10 est detecté comme une menace /!\

## Ressources

https://www.root-me.org/fr/Documentation/Applicatif/RunPE <br>
CreateProcess: https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createprocessa<br>
flag de création :  https://docs.microsoft.com/fr-fr/windows/win32/procthread/process-creation-flags<br>
PE format: https://fr.wikipedia.org/wiki/Portable_Executable<br>
PEB explication: https://ntopcode.wordpress.com/2018/02/26/anatomy-of-the-process-environment-block-peb-windows-internals/<br>
IMAGE_DOS_HEADER: https://www.nirsoft.net/kernel_struct/vista/IMAGE_DOS_HEADER.html<br>
IMAGE_NT_HEADER: https://docs.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-image_nt_headers32<br>
IMAGE_OPTIONAL_HEADER: https://docs.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-image_optional_header32<br>
IMAGE_FILE_HEADER: https://docs.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-image_file_header<br>
IMAGE_SECTION_HEADER: https://docs.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-image_section_header<br>
CONTEXT structure : https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/ns-ntddk-context<br>
VirtualAlloc: https://docs.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualalloc<br>
VirtualAllocEx: https://docs.microsoft.com/fr-fr/windows/win32/api/memoryapi/nf-memoryapi-virtualallocex<br>
ReadProcessMemory: https://docs.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-readprocessmemory<br>
WriteProcessMemory: https://docs.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-writeprocessmemory<br>
SetThreadContext: https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-setthreadcontext<br>
