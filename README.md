## Geek
Windows C++ 安全工具库

### 施工中...
这意味着代码可能随时发生变化，仅供学习参考

## Hook
实现了一些Windows R3下常用的hook方式：
### Inline Hook
**通用Inline Hook框架**
1. 支持x86/x86_64
2. 线程安全设计
3. 支持callback中重入原函数(基于动态TLS)
4. 支持上下文修改

### IAT hook
**通用IAT hook框架**

### ...

## Sign Searcher
**特征码搜索**
1. 支持`**`、`??`模糊匹配字节
2. 支持`&`定位返回基地址
3. 支持`*`重复字节

## PE
**PE工具库**
1. 配合`Process`实现内存加载
2. ...

## Other
更多请自行探索...