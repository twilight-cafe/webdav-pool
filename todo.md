# 阶段 ②③④ 完成情况

## 阶段 ②：DAV 方法实现（已完成并验证）

目标：RFC 4918 Class 1 全部方法，内容/请求体/响应体一律流式。

已落地：

- `fsutil`：`Fd`/`DirStream` RAII；`resolve_path` 逐级 `openat(O_PATH|O_NOFOLLOW)` + `fstat` 判符号链接；严格 percent 解码；`remove_tree`/`copy_tree`（显式受控深度 64）。
- `http`：`Reader`/`BodyReader`（Content-Length 与 chunked 流式解码，16 KB 固定缓冲）、`Response`（定长/chunked 流式写、HEAD 只发头）。
- `dav`：OPTIONS、GET、HEAD、PUT、DELETE、MKCOL、PROPFIND、PROPPATCH、COPY、MOVE。
- `server`：`read_header` 解析 + 每请求 `Response` 上下文、`Expect: 100-continue`、keep-alive 判定。
- PUT：同目录临时文件（`O_CREAT|O_EXCL|O_NOFOLLOW`，0600）+ `renameat` 原子替换；中途失败/断连删除临时文件。

已完成：

- [x] 编译零告警（`-Wall -Wextra -Wpedantic -Werror`）——clean rebuild 零告警。
- [x] `ctest --preset release` 全绿（新增 `tests/test_dav.cpp`：各方法正常路径 + 错误分支）。
- [x] 手工冒烟：curl 逐方法验证。
- [x] 语义复核：集合 GET→405；PROPFIND 缺省/infinity→403；未知属性→404 propstat；`Overwrite: F`→412；跨 host `Destination`→502；不支持方法→405+`Allow`；`Range` 非法/多重→200 整实体。
- [x] README 更新"支持 / 不支持特性表"。

## 阶段 ③：路径安全加固

- [x] 全量审查取文件入口，确认无 "canonicalize 后按原路径打开" 的 TOCTOU 写法。
- [x] COPY/MOVE 的 `Destination` 必须落在本用户根目录内；越界/指向他人 → 403；跨 host → 502。
- [x] 符号链接策略固化并写入 README：不跟随；出现在路径任一段或作为叶子 → 403；目录列举跳过；递归删/复制遇符号链接 → 403。
- [x] "目录被替换为符号链接" 竞态用例：并发替换中间目录，断言不逃逸。
- [x] 响应不回显服务器绝对路径、不泄露其他用户名。
- [x] 逃逸用例固化：`..`、绝对路径、NUL、空段、`.`、超长路径、双重编码、`%2f` 变体 → 403。
- [x] 同用户内合法路径（含空格、中文、`%20`）仍可正常访问，避免加固误伤。

## 阶段 ④：测试补齐 + 覆盖率 + 内存达标

- [x] `scripts/coverage.sh`：vendored lcov + genhtml 输出 `build/coverage/`，断言 `src/` + `include/` 行覆盖 == 100.0%，不达标非 0 退出。
- [x] `asan` preset：全部测试通过且 **0 leak**（`ASAN_OPTIONS=detect_leaks=1`）。
- [x] `scripts/memcheck.sh`：16 并发 = 3×512 MB 上传 + 3×512 MB 下载 + 1000 次 `PROPFIND Depth:1`（1000 条目目录）+ 200 次认证；采样 `/proc/<pid>/status` 的 `VmHWM`，断言 < 10 MB（大文件用生成/稀疏文件，不入库）。
- [x] 补齐测试：各方法错误分支（401/403/404/405/409/412/415/416/500/507）、配置解析全部失败分支、`--version`、`main()` 覆盖。
- [x] 并发测试：≥2 线程 PUT 同一路径、PUT 与 GET 并发、并发认证触发限流/退避。
- [x] 上传中断：无残留临时文件、fd 计数回到基线（`/proc/self/fd`）。
- [x] 故障注入（文件系统/时钟/socket）覆盖 ENOSPC→507、写失败、rename 失败等难触发分支；无死代码。
- [x] README：内存预算表（代码段 + 全局数据 + N×每连接缓冲）+ 实测数据 + 空载 RSS 基线（实测 4724 kB）+ 安全模型与残余风险 + nginx 示例校对。
- [x] 交付自查报告：clean 构建、ctest、覆盖率摘要、asan 摘要、VmHWM 实测值。

## 交付物清单（最终）

`CMakeLists.txt`、`CMakePresets.json`、`include/`、`src/`、`tests/`、`scripts/coverage.sh`、`scripts/memcheck.sh`、`config.example.json`、`nginx.conf.example`、`webdavd.service.example`、`README.md`、`SELF_CHECK.md`、`todo.md`。
