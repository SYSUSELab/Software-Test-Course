// vulnerable.c 
#include <stdint.h> 
#include <stddef.h> 
#include <string.h> 
// 一个有漏洞的函数 
void ProcessString(const char *str, size_t len) { 
    char buffer[10]; 
    // 漏洞：没有检查长度！ 
    memcpy(buffer, str, len); 
} 
// Fuzz Target 
int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) { 
    //待填写
} 
