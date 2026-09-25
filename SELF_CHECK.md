# webdavd 交付自查报告

## 1. 构建

```sh
cmake --build --preset release --clean-first
```

- 编译选项：`-Wall -Wextra -Wpedantic -Werror`
- 结果：完全重新编译并链接成功，**零告警**。
- 依赖：Boost.Asio/Beast、nlohmann/json、GoogleTest 均由 FetchContent 提供。

## 2. Release 测试

```sh
ctest --preset release
```

- 结果：**155/155 passed**，0 failed。
- 覆盖的方法：OPTIONS / GET / HEAD / PUT / DELETE / MKCOL / PROPFIND /
  PROPPATCH / COPY / MOVE，以及认证、配置、HTTP 解析、文件系统故障注入、
  并发 PUT、PUT/GET 并发、中断上传清理、符号链接竞态等错误分支。

## 3. 覆盖率

```sh
./scripts/coverage.sh
```

- 结果：**lines: 100.0% (1878 of 1878 lines)**，`src/` + `include/` 全部行覆盖。
- 脚本在 lcov 1.16 下运行；coverage preset 使用
  `-fprofile-update=atomic`，多线程测试不再产生 gcov negative-count /
  checksum 警告。
- HTML 报告：`build/coverage/html/index.html`。

## 4. ASan / UBSan

```sh
cmake --preset asan
cmake --build --preset asan
ASAN_OPTIONS=detect_leaks=1:abort_on_error=1 UBSAN_OPTIONS=print_stacktrace=1 \
  ctest --preset asan
```

- 结果：**155/155 passed**，0 failed。
- 日志中无 AddressSanitizer、LeakSanitizer 或 UBSan 报错，**0 leak**。

## 5. 内存门禁

```sh
./scripts/memcheck.sh
```

负载：

- 16 个并发 worker；
- 3 x 512 MiB PUT 上传；
- 3 x 512 MiB GET 下载；
- 1000 次 `PROPFIND Depth: 1`（1000 条目目录）；
- 200 次有效 Basic 认证请求。

实测：

- `/proc/<pid>/status` `VmHWM` 峰值：**5856 kB ≈ 5.7 MiB**；
- 门限：**< 10240 kB (10 MiB)**；
- 结果：通过。
- 空载基线：`VmRSS`/`VmHWM` **4724 kB ≈ 4.6 MiB**。

## 6. 手工 curl 冒烟

用真实 `webdavd` + curl 逐项验证，27/27 通过：

- OPTIONS 200 + `DAV: 1` + `Allow`；
- PUT 新建 201 / 覆盖 204；
- GET 200 / HEAD 200；
- 集合 GET 405；
- MKCOL 201 / 已存在 405；
- PROPFIND Depth:0 207 / 缺省 Depth 403 / infinity 403；
- PROPPATCH 207（属性 403）；
- COPY 201 / `Overwrite: F` 412 / 跨 host `Destination` 502 /
  越界 `Destination` 403；
- MOVE 201；
- DELETE 204；
- LOCK/TRACE 等不支持方法 405 + `Allow`；
- 非法和多 Range 200 整实体；
- 符号链接 403；
- 含空格、中文且 percent-encoded 的合法路径 200。

## 7. 路径安全与 TOCTOU 审查

- 所有请求路径只做一次严格 percent-decode；拒绝 NUL、超长、空段、
  `.`/`..`、编码斜杠和 `%25` 双重编码输入。
- 逐段 `openat(O_PATH|O_NOFOLLOW)` 后 `fstat`，持有实际目录 fd，
  后续 `openat` / `renameat` / `unlinkat` / `mkdirat` 均相对该 fd 执行，
  不存在 "canonicalize 后按原路径重新打开" 的模式。
- 叶子操作一律 `O_NOFOLLOW`；递归删除/复制中遇到符号链接立即失败。
- `Destination` 在认证用户自己的 root fd 下重新解析；跨 host 502，
  越界或指向 root 本身 403。
- `DavTest.ConcurrentIntermediateSymlinkSwapCannotEscape` 实现了并发
  rename + symlink 替换中间目录的竞态测试，确认不会写入符号链接目标。
- 错误响应不包含服务端绝对路径或其他用户 root / 用户名。

## 8. 残余风险

- 应用层不实现 TLS，必须部署在 nginx/其他 TLS 反向代理之后。
- 不支持 LOCK/UNLOCK、ACL、SEARCH、versioning、dead-property 持久化。
- 不评估 `If` / `If-Match` / `If-None-Match`，不支持 multi-range / If-Range /
  partial PUT。
- 文件名中的字面 `%` 无法访问（`%25` 被当作双重编码攻击拒绝）；
  空格、中文等按标准 percent-encoding 正常。
- 跨设备 MOVE 的 copy fallback 或递归 COPY 失败时，目标端可能残留部分树；
  源端不受影响，需客户端清理残留目标。
- `PROPFIND Depth: 1` 对超大目录仍可能产生大量 CPU/网络开销；进程内
  没有请求限速和配额，部署时应交给 nginx 限制。
- 安全边界假设本地 root 管理员可信；拥有 root 目录写权限的本地用户自然
  可以增删文件。

## 9. 结论

Release 构建零告警、155/155 测试通过、`src/`+`include/` 行覆盖率 100%、
ASan/UBSan 零报错零 leak、16 并发大流量下 `VmHWM` 5.7 MiB，满足交付要求。
