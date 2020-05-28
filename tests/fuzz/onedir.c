#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <dirent.h>
#include <unistd.h>

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size);

int main(int argc, char** argv)
{
    FILE * fp;
    uint8_t Data[0x1000];
    size_t Size;
    DIR *d;
    struct dirent *dir;
    int r = 0;
    int i;

    if (argc != 2) {
        return 1;
    }

    d = opendir(argv[1]);
    if (d == NULL) {
        printf("Invalid directory\n");
        return 2;
    }
    if (chdir(argv[1]) != 0) {
        closedir(d);
        printf("Invalid directory\n");
        return 2;
    }

    printf("Starting directory %s\n", argv[1]);
    while((dir = readdir(d)) != NULL) {
        //opens the file, get its size, and reads it into a buffer
        if (dir->d_type != DT_REG) {
            continue;
        }
        //printf("Running file %s\n", dir->d_name);
        fflush(stdout);
        fp = fopen(dir->d_name, "rb");
        if (fp == NULL) {
            r = 3;
            break;
        }
        if (fseek(fp, 0L, SEEK_END) != 0) {
            fclose(fp);
            r = 4;
            break;
        }
        Size = ftell(fp);
        if (Size == (size_t) -1) {
            fclose(fp);
            r = 5;
            break;
        } else if (Size > 0x1000) {
            fclose(fp);
            continue;
        }
        if (fseek(fp, 0L, SEEK_SET) != 0) {
            fclose(fp);
            r = 7;
            break;
        }
        if (fread(Data, Size, 1, fp) != 1) {
            fclose(fp);
            r = 8;
            break;
        }

        //lauch fuzzer
        LLVMFuzzerTestOneInput(Data, Size);
        fclose(fp);
    }
    closedir(d);
    printf("Ok : whole directory finished %s\n", argv[1]);
    return r;
}

