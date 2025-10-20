#include <cstdint>
#include <cstddef>
#include <string>

// 1. 包含 FuzzedDataProvider，这是 LibFuzzer 的一个辅助工具
#include <fuzzer/FuzzedDataProvider.h>

// 2. 包含我们要测试的目标代码
#include "socperf_lru_cache.h"

// 定义我们要 Fuzz 的 Key 和 Value 类型
// 我们选择简单的类型：uint32_t 作为 Key，std::string 作为 Value
using FuzzKey = uint32_t;
using FuzzValue = std::string;

// 3. 这是 LibFuzzer 的主入口点
// 每次执行，LibFuzzer 都会生成新的 Data 和 Size
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {

    // 4. 初始化 FuzzedDataProvider
    FuzzedDataProvider fdp(Data, Size);

    // 5. 设置缓存容量，也由 Fuzzer 决定（比如 1 到 128 之间）
    // 我们不使用 `static` 缓存，而是为每次输入创建一个新缓存
    // 这样可以测试不同容量和构造函数
    size_t capacity = fdp.ConsumeIntegralInRange<size_t>(1, 128);
    OHOS::SOCPERF::SocPerfLRUCache<FuzzKey, FuzzValue> cache(capacity);

    // 6. 模拟一系列操作，直到 Fuzzer 提供的
    //    数据耗尽 (fdp.remaining_bytes() > 0)
    //    我们最多执行 200 次操作，防止超时
    int operations = 0;
    while (fdp.remaining_bytes() > 0 && operations++ < 200) {

        // 7. 让 Fuzzer 决定下一步是 'put' 还是 'get'
        bool is_put = fdp.ConsumeBool();

        if (is_put) {
            // 模拟 'put'
            // 从 Fuzzer 数据中提取 Key
            FuzzKey key = fdp.ConsumeIntegral<FuzzKey>();

            // 从 Fuzzer 数据中提取 Value (最多 100 字节)
            FuzzValue value = fdp.ConsumeRandomLengthString(100);

            // 调用目标 API
            cache.put(key, value);

        } else {
            // 模拟 'get'
            // 从 Fuzzer 数据中提取 Key
            FuzzKey key = fdp.ConsumeIntegral<FuzzKey>();

            // 准备一个变量来接收 'get' 的结果
            FuzzValue out_value;

            // 调用目标 API
            cache.get(key, out_value);
        }
    }

    // 8. 必须返回 0
    return 0;
}