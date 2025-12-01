//================================================================ 
// simple_json_fuzzer.cpp 
// 简化的 JSON 文档数据库 Fuzzer Demo 
//================================================================ 
#include <fuzzer/FuzzedDataProvider.h> 
#include <cstdint> 
#include <cstddef> 
#include <cstring> 
#include <string> 
#include <iostream> 
//--------------------------------------------------- 
// 第1部分：模拟 GaussDB API（简化版） 
//--------------------------------------------------- 
// 模拟的数据库句柄 
typedef void* GRD_DB; 
// 模拟的 JSON 文档解析器 
bool ParseJSONDocument(const char *json, size_t len) { 
    if (!json || len == 0) { 
        return false; 
    }
    // 检查基本格式 
    if (json[0] != '{') { 
        return false; 
    }
    // 检查是否以 '}' 结尾 
    if (len > 0 && json[len-1] != '}') { 
        return false; 
    }
    // 检查嵌套深度（简单计数） 
    int depth = 0; 
    int maxDepth = 0; 
    for (size_t i = 0; i < len; i++) { 
        if (json[i] == '{' || json[i] == '[') { 
            depth++; 
            if (depth > maxDepth) maxDepth = depth; 
            // 限制嵌套深度为 100 层 
            if (depth > 100) { 
                return false; 
            } 
        } else if (json[i] == '}' || json[i] == ']') { 
            depth--; 
        } 
    }
    return true; 
} 
// 模拟插入文档的 API 
int GRD_InsertDoc(GRD_DB *db, const char *collectionName, 
                  const char *document, uint32_t flags) { 
    // 验证参数（静默失败，避免终端噪音） 
    if (!db || !collectionName || !document) { 
        return -1; 
    }
    size_t docLen = strlen(document); 
    // 检查文档长度 
    if (docLen == 0 || docLen > 1024 * 1024) {  // 1MB 限制 
        return -1; 
    }
    // 解析 JSON 
    if (!ParseJSONDocument(document, docLen)) { 
        return -1; 
    }
    return 0;  // 成功 
} 
//--------------------------------------------------- 
// 第2部分：Fuzz Target（从真实代码简化） 
//--------------------------------------------------- 
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) { 
    // 待测试
    return 0; 
} 