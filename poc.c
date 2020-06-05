#include <stdlib.h>
#include <stdio.h>
#include <windows.h>

// gcc -O2 -s -mwindows poc.c -o poc.exe

int main()
{
    MessageBox(NULL, "Hellow World", NULL, MB_OK);
    
    FILE* fp = fopen("poc.txt", "w");
    if(fp != NULL){
        fprintf(fp, "hello world\n");
    }
    
    fclose(fp);
    return 0;
}
