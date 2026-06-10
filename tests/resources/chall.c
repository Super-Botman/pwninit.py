// gcc chall.c -o chall -fno-stack-protector -z execstack -no-pie

#include <stdio.h>
#include <unistd.h>

__attribute__((used)) void gagdets() {
    __asm__ volatile (
        "pop %rdi\n\t"
        "pop %rsi\n\t"
        "ret\n\t"
    );
}

void win(unsigned int arg1, unsigned int arg2) {
    if (arg1 == 0xdeadbeef && arg2 == 0xcafebabe) {
        puts("SUCCESS");
    } else {
        puts("FAIL");
    }
}

int main() {
    char buf[100];

    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stdin, NULL, _IONBF, 0);

    puts("TURBO IMPOSSIBLE CHALL");
    printf("Diagnostic stack leak: %p\n", (void*)buf);

    fgets((char *) stdin, 200, stdin);
    fgets(buf, 200, stdin);
    
    return 0;
}
