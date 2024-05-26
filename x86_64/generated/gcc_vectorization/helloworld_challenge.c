#include <stdio.h>
int main(int argc, char** argv){
    const int N = 1320;
    char s[N];
    for (short i = 0; i < N - 1; ++i)
        s[i] = i + 1;
    s[N - 1] = '\0';
    printf(s);
}