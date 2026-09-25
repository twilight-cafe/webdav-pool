#include "webdav/dav.hpp"

#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#include <algorithm>
#include <atomic>
#include <cerrno>
#include <cctype>
#include <cstdio>
#include <cstring>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "webdav/fault.hpp"

namespace webdav {

namespace {

std::atomic<unsigned> g_temp_counter{0};

http::status status_for_path(PathStatus status, bool parent_scope) {
  if (status == PathStatus::kBadRequest) {
    return http::status::bad_request;
  }
  if (status == PathStatus::kNotFound || status == PathStatus::kNotDirectory) {
    return parent_scope ? http::status::conflict : http::status::not_found;
  }
  return http::status::forbidden;
}

http::status status_for_errno(int error, bool allow_conflict) {
  switch (error) {
    case ENOENT:
      return http::status::not_found;
    case EACCES:
    case EPERM:
    case kTreeSymlink:
    case kTreeDepthExceeded:
      return http::status::forbidden;
    case EEXIST:
    case ENOTEMPTY:
      return allow_conflict ? http::status::conflict : http::status::method_not_allowed;
    case ENOSPC:
    case EDQUOT:
      return http::status::insufficient_storage;
    default:
      return http::status::internal_server_error;
  }
}

void method_not_allowed(Response& response) {
  if (response.has("Allow") == false) {
    response.set("Allow", std::string(kAllowMethods));
  }
  (void)response.send_text(http::status::method_not_allowed, "Method Not Allowed\n");
}

std::string header_value(const http::request_header<>& head, http::field field) {
  const auto value = head[field];
  return std::string(value.data(), value.size());
}

bool iequals(std::string_view a, std::string_view b) {
  if (a.size() != b.size()) {
    return false;
  }
  for (std::size_t i = 0; i < a.size(); ++i) {
    const auto ca = static_cast<unsigned char>(a[i]);
    const auto cb = static_cast<unsigned char>(b[i]);
    if (std::tolower(ca) != std::tolower(cb)) {
      return false;
    }
  }
  return true;
}

std::string_view mime_for(std::string_view name) {
  const std::size_t dot = name.rfind('.');
  std::string extension;
  if (dot != std::string_view::npos) {
    for (std::size_t i = dot + 1; i < name.size(); ++i) {
      extension.push_back(static_cast<char>(std::tolower(static_cast<unsigned char>(name[i]))));
    }
  }
  static constexpr std::pair<std::string_view, std::string_view> kTable[] = {
      {"html", "text/html"},
      {"htm", "text/html"},
      {"css", "text/css"},
      {"js", "text/javascript"},
      {"json", "application/json"},
      {"txt", "text/plain"},
      {"xml", "application/xml"},
      {"pdf", "application/pdf"},
      {"png", "image/png"},
      {"jpg", "image/jpeg"},
      {"jpeg", "image/jpeg"},
      {"gif", "image/gif"},
      {"svg", "image/svg+xml"},
      {"webp", "image/webp"},
      {"ico", "image/x-icon"},
      {"zip", "application/zip"},
      {"gz", "application/gzip"},
      {"tar", "application/x-tar"},
      {"mp3", "audio/mpeg"},
      {"mp4", "video/mp4"},
      {"wasm", "application/wasm"},
      {"csv", "text/csv"},
      {"md", "text/markdown"},
  };
  for (const auto& entry : kTable) {
    if (extension == entry.first) {
      return entry.second;
    }
  }
  return "application/octet-stream";
}

std::string xml_escape(std::string_view input) {
  std::string out;
  out.reserve(input.size());
  for (const char c : input) {
    switch (c) {
      case '&':
        out.append("&amp;");
        break;
      case '<':
        out.append("&lt;");
        break;
      case '>':
        out.append("&gt;");
        break;
      case '"':
        out.append("&quot;");
        break;
      case '\'':
        out.append("&apos;");
        break;
      default:
        out.push_back(c);
        break;
    }
  }
  return out;
}  // LCOV_EXCL_LINE

std::string_view local_name(std::string_view qualified) {
  const std::size_t colon = qualified.rfind(':');
  return colon == std::string_view::npos ? qualified : qualified.substr(colon + 1);
}

struct PropRequest {
  enum class Kind { kAllProp, kPropName, kPropList };
  Kind kind{Kind::kAllProp};
  std::vector<std::string> names;
};

constexpr std::string_view kDefaultProps[] = {"resourcetype",    "displayname", "creationdate",
                                             "getlastmodified",  "getetag",     "getcontentlength",
                                             "getcontenttype"};

// Finds the opening tag whose local name (namespace prefix ignored) is
// `local`, so "<D:prop>" matches but "<D:propfind>" does not.
std::size_t find_local_tag(std::string_view body, std::string_view local, std::size_t from = 0) {
  std::size_t position = from;
  while (position < body.size()) {
    const std::size_t found = body.find('<', position);
    if (found == std::string_view::npos) {
      return std::string_view::npos;
    }
    const std::size_t name_start = found + 1;
    if (name_start >= body.size()) {
      return std::string_view::npos;
    }
    const char marker = body[name_start];
    if (marker == '/' || marker == '!' || marker == '?') {
      position = name_start + 1;
      continue;
    }
    std::size_t end = name_start;
    while (end < body.size() && body[end] != '>' && body[end] != '/' && body[end] != ' ' &&
           body[end] != '\t' && body[end] != '\n' && body[end] != '\r') {
      ++end;
    }
    if (local_name(body.substr(name_start, end - name_start)) == local) {
      return found;
    }
    position = end;
  }
  return std::string_view::npos;
}

// Collects the element names appearing inside `body`, skipping closing tags,
// comments, processing instructions and the names in `skip`.
void collect_names(std::string_view body, const std::vector<std::string_view>& skip,
                   std::vector<std::string>& out) {
  std::size_t position = 0;
  while (position < body.size()) {
    const std::size_t open = body.find('<', position);
    if (open == std::string_view::npos) {
      return;
    }
    const char marker = open + 1 < body.size() ? body[open + 1] : '\0';
    if (marker == '/' || marker == '!' || marker == '?') {
      position = open + 1;
      continue;
    }
    std::size_t end = open + 1;
    while (end < body.size() && body[end] != '>' && body[end] != '/' && body[end] != ' ' &&
           body[end] != '\t' && body[end] != '\n' && body[end] != '\r') {
      ++end;
    }
    const std::string_view name = body.substr(open + 1, end - (open + 1));
    bool skip_name = name.empty();
    for (const std::string_view candidate : skip) {
      if (name == candidate || local_name(name) == candidate) {
        skip_name = true;
        break;
      }
    }
    if (!skip_name) {
      out.emplace_back(name);
    }
    position = end;
  }
}

bool parse_prop_request(std::string_view body, PropRequest& out) {
  if (body.empty()) {
    out.kind = PropRequest::Kind::kAllProp;
    return true;
  }
  if (find_local_tag(body, "allprop") != std::string_view::npos) {
    out.kind = PropRequest::Kind::kAllProp;
    return true;
  }
  if (find_local_tag(body, "propname") != std::string_view::npos) {
    out.kind = PropRequest::Kind::kPropName;
    return true;
  }
  const std::size_t open = find_local_tag(body, "prop");
  if (open == std::string_view::npos) {
    return false;
  }
  const std::size_t end = body.find('>', open);
  if (end == std::string_view::npos) {
    return false;
  }
  collect_names(body.substr(end + 1), {"prop", "propfind", "propertyupdate", "set", "remove"},
                out.names);
  if (out.names.empty()) {
    return false;
  }
  out.kind = PropRequest::Kind::kPropList;
  return true;
}

std::string render_property(std::string_view raw, std::string_view display_name,
                            const struct stat& info, bool is_collection) {
  const std::string_view local = local_name(raw);
  std::string value;
  if (local == "resourcetype") {
    value = is_collection ? "<D:collection/>" : "";
  } else if (local == "displayname") {
    value = xml_escape(display_name);
  } else if (local == "creationdate") {
    value = format_iso8601(info.st_ctime);
  } else if (local == "getlastmodified") {
    value = format_http_date(info.st_mtime);
  } else if (local == "getetag") {
    value = xml_escape(format_etag(static_cast<std::uint64_t>(info.st_size), info.st_mtim));
  } else if (local == "getcontentlength") {
    value = is_collection ? "" : std::to_string(info.st_size);
  } else if (local == "getcontenttype") {
    value = is_collection ? "" : std::string(mime_for(display_name));
  } else {
    return std::string();
  }
  std::string out = "<D:";
  out.append(local);
  out.push_back('>');
  out.append(value);
  out.append("</D:");
  out.append(local);
  out.push_back('>');
  return out;
}

void emit_resource(Response& response, const std::string& href, const std::string& name,
                   const struct stat& info, bool is_collection, const PropRequest& request) {
  std::string xml;
  xml.reserve(512);
  xml.append("<D:response><D:href>");
  xml.append(xml_escape(href));
  xml.append("</D:href>");

  std::string ok_props;
  std::string missing;
  if (request.kind == PropRequest::Kind::kPropName) {
    for (const std::string_view prop : kDefaultProps) {
      ok_props.append("<D:");
      ok_props.append(prop);
      ok_props.append("/>");
    }
  } else if (request.kind == PropRequest::Kind::kAllProp) {
    for (const std::string_view prop : kDefaultProps) {
      if (!is_collection || (prop != "getcontentlength" && prop != "getcontenttype")) {
        ok_props.append(render_property(prop, name, info, is_collection));
      }
    }
  } else {
    for (const std::string& raw : request.names) {
      const std::string rendered = render_property(raw, name, info, is_collection);
      if (!rendered.empty()) {
        ok_props.append(rendered);
      } else {
        missing.push_back('<');
        missing.append(raw);
        if (raw.find(':') == std::string::npos) {
          missing.append(" xmlns=\"DAV:\"");
        }
        missing.append("/>");
      }
    }
  }

  if (!ok_props.empty()) {
    xml.append("<D:propstat><D:prop>");
    xml.append(ok_props);
    xml.append("</D:prop><D:status>HTTP/1.1 200 OK</D:status></D:propstat>");
  }
  if (!missing.empty()) {
    xml.append("<D:propstat><D:prop>");
    xml.append(missing);
    xml.append("</D:prop><D:status>HTTP/1.1 404 Not Found</D:status></D:propstat>");
  }
  xml.append("</D:response>");
  (void)response.write_chunk(xml);
}

std::string build_href(std::string_view base, bool is_collection) {
  std::string href = percent_encode(base);
  if (is_collection && (href.empty() || href.back() != '/')) {
    href.push_back('/');
  }
  return href;
}  // LCOV_EXCL_LINE

struct ByteRange {
  bool valid{false};
  std::uint64_t first{0};
  std::uint64_t last{0};
};

bool parse_uint(std::string_view text, std::uint64_t& out) {
  if (text.empty()) {
    return false;
  }
  std::uint64_t value = 0;
  for (const char c : text) {
    if (c < '0' || c > '9') {
      return false;
    }
    value = value * 10 + static_cast<std::uint64_t>(c - '0');
  }
  out = value;
  return true;
}

ByteRange parse_range(std::string_view value, std::uint64_t size) {
  ByteRange range;
  if (value.size() < 6 || value.substr(0, 6) != "bytes=") {
    return range;
  }
  const std::string_view spec = value.substr(6);
  if (spec.find(',') != std::string_view::npos) {
    return range;
  }
  const std::size_t dash = spec.find('-');
  if (dash == std::string_view::npos) {
    return range;
  }
  const std::string_view first_text = spec.substr(0, dash);
  const std::string_view last_text = spec.substr(dash + 1);
  if (first_text.empty()) {
    std::uint64_t suffix = 0;
    if (!parse_uint(last_text, suffix) || suffix == 0 || size == 0) {
      return range;
    }
    range.first = suffix >= size ? 0 : size - suffix;
    range.last = size - 1;
    range.valid = true;
    return range;
  }
  if (!parse_uint(first_text, range.first) || range.first >= size) {
    return range;
  }
  if (last_text.empty()) {
    range.last = size - 1;
    range.valid = true;
    return range;
  }
  if (!parse_uint(last_text, range.last) || range.last < range.first) {
    return range;
  }
  range.last = std::min(range.last, size - 1);
  range.valid = true;
  return range;
}

void handle_options(Response& response) {
  response.result(http::status::ok);
  response.set("DAV", "1");
  response.set("MS-Author-Via", "DAV");
  response.set("Allow", std::string(kAllowMethods));
  response.set("Content-Length", "0");
  (void)response.write_head();
}

void handle_get(DavContext& ctx, Response& response, bool head_only) {
  const Target target = resolve_path(ctx.root, std::string(ctx.head.target()));
  if (!target.ok()) {
    (void)response.send_text(status_for_path(target.status, false), "Error\n");
    return;
  }
  const bool collection = target.is_root || S_ISDIR(target.info.st_mode);
  if (collection || !target.exists) {
    if (collection) {
      method_not_allowed(response);
    } else {
      (void)response.send_text(http::status::not_found, "Not Found\n");
    }
    return;
  }
  if (!S_ISREG(target.info.st_mode)) {
    (void)response.send_text(http::status::forbidden, "Forbidden\n");
    return;
  }

  Fd file = open_leaf(target.parent, target.leaf, O_RDONLY);
  if (!file.valid()) {
    (void)response.send_text(errno == ENOENT ? http::status::not_found : http::status::forbidden,
                             "Error\n");
    return;
  }
  struct stat info {};
  if (fs_fstat(file.get(), &info) != 0 || !S_ISREG(info.st_mode)) {
    (void)response.send_text(http::status::forbidden, "Forbidden\n");
    return;
  }

  const std::uint64_t size = static_cast<std::uint64_t>(info.st_size);
  ByteRange range;
  if (const auto raw = ctx.head[http::field::range]; !raw.empty()) {
    range = parse_range(std::string_view(raw.data(), raw.size()), size);
  }
  std::uint64_t first = 0;
  std::uint64_t length = size;
  if (range.valid) {
    first = range.first;
    length = range.last - range.first + 1;
  }

  response.result(range.valid ? http::status::partial_content : http::status::ok);
  response.set("Content-Type", std::string(mime_for(target.leaf)));
  response.set("Content-Length", std::to_string(length));
  response.set("Last-Modified", format_http_date(info.st_mtime));
  response.set("ETag", format_etag(size, info.st_mtim));
  response.set("Accept-Ranges", "bytes");
  if (range.valid) {
    response.set("Content-Range", "bytes " + std::to_string(first) + "-" +
                                      std::to_string(first + length - 1) + "/" +
                                      std::to_string(size));
  }
  if (!response.write_head() || head_only) {
    return;
  }

  std::vector<char> buffer(kIoBufferSize);
  std::uint64_t offset = first;
  std::uint64_t left = length;
  while (left > 0) {
    const std::size_t want =
        static_cast<std::size_t>(std::min<std::uint64_t>(left, buffer.size()));
    const ssize_t got = fs_pread(file.get(), buffer.data(), want, static_cast<off_t>(offset));
    if (got < 0) {
      if (errno == EINTR) {
        continue;
      }
      break;
    }
    if (got == 0) {
      break;
    }
    if (!response.write(buffer.data(), static_cast<std::size_t>(got))) {
      break;
    }
    offset += static_cast<std::uint64_t>(got);
    left -= static_cast<std::uint64_t>(got);
  }
}

void handle_put(DavContext& ctx, Response& response) {
  const Target target = resolve_path(ctx.root, std::string(ctx.head.target()));
  if (!target.ok()) {
    (void)response.send_text(status_for_path(target.status, true), "Error\n");
    return;
  }
  if (target.is_root || (target.exists && S_ISDIR(target.info.st_mode))) {
    method_not_allowed(response);
    return;
  }
  if (target.exists && !S_ISREG(target.info.st_mode)) {
    (void)response.send_text(http::status::forbidden, "Forbidden\n");
    return;
  }
  if (!ctx.body.has_body()) {
    (void)response.send_text(http::status::length_required, "Length Required\n");
    return;
  }

  const unsigned serial = g_temp_counter.fetch_add(1);
  char temp_name[64];
  std::snprintf(temp_name, sizeof(temp_name), ".webdav-tmp-%ld-%u", static_cast<long>(::getpid()),
                serial);

  Fd out = open_leaf(target.parent, temp_name, O_WRONLY | O_CREAT | O_EXCL, 0600);
  if (!out.valid()) {
    (void)response.send_text(http::status::insufficient_storage, "Cannot create temporary file\n");
    return;
  }

  std::vector<char> buffer(kIoBufferSize);
  int failure = 0;
  for (;;) {
    std::size_t got = 0;
    if (!ctx.body.read(buffer.data(), buffer.size(), got)) {
      failure = EIO;
      break;
    }
    if (got == 0) {
      break;
    }
    std::size_t written = 0;
    while (written < got) {
      const ssize_t n =
          fs_write(out.get(), buffer.data() + written, static_cast<std::size_t>(got - written));
      if (n < 0) {
        if (errno == EINTR) {
          continue;
        }
        failure = errno;
        break;
      }
      written += static_cast<std::size_t>(n);
    }
    if (failure != 0) {
      break;
    }
  }
  out.reset();

  if (failure != 0) {
    (void)fs_unlinkat(target.parent.get(), temp_name, 0);
    if (failure == EIO) {
      response.set_keep_alive(false);
      (void)response.send_text(http::status::bad_request, "Incomplete body\n");
    } else {
      (void)response.send_text(status_for_errno(failure, false), "Write failed\n");
    }
    return;
  }

  if (fs_renameat(target.parent.get(), temp_name, target.parent.get(), target.leaf.c_str()) != 0) {
    const int error = errno;
    (void)fs_unlinkat(target.parent.get(), temp_name, 0);
    (void)response.send_text(status_for_errno(error, false), "Rename failed\n");
    return;
  }
  response.result(target.exists ? http::status::no_content : http::status::created);
  response.set("Content-Length", "0");
  (void)response.write_head();
}

void handle_delete(DavContext& ctx, Response& response) {
  const Target target = resolve_path(ctx.root, std::string(ctx.head.target()));
  if (!target.ok()) {
    (void)response.send_text(status_for_path(target.status, false), "Error\n");
    return;
  }
  if (target.is_root) {
    (void)response.send_text(http::status::forbidden, "Cannot delete the root\n");
    return;
  }
  if (!target.exists) {
    (void)response.send_text(http::status::not_found, "Not Found\n");
    return;
  }
  if (ctx.body.has_body()) {
    response.set_keep_alive(false);
  }
  const int rc = remove_tree(target.parent, target.leaf);
  if (rc != 0) {
    (void)response.send_text(status_for_errno(rc, false), "Delete failed\n");
    return;
  }
  response.result(http::status::no_content);
  response.set("Content-Length", "0");
  (void)response.write_head();
}

void handle_mkcol(DavContext& ctx, Response& response) {
  if (ctx.body.has_body()) {
    response.set_keep_alive(false);
    (void)response.send_text(http::status::unsupported_media_type, "Body not supported\n");
    return;
  }
  const Target target = resolve_path(ctx.root, std::string(ctx.head.target()));
  if (!target.ok()) {
    (void)response.send_text(status_for_path(target.status, true), "Error\n");
    return;
  }
  if (target.is_root || target.exists) {
    method_not_allowed(response);
    return;
  }
  if (fs_mkdirat(target.parent.get(), target.leaf.c_str(), 0777) != 0) {
    (void)response.send_text(status_for_errno(errno, true), "Create failed\n");
    return;
  }
  response.result(http::status::created);
  response.set("Content-Length", "0");
  (void)response.write_head();
}

void handle_propfind(DavContext& ctx, Response& response) {
  const Target target = resolve_path(ctx.root, std::string(ctx.head.target()));
  if (!target.ok()) {
    (void)response.send_text(status_for_path(target.status, false), "Error\n");
    return;
  }
  if (!target.exists) {
    (void)response.send_text(http::status::not_found, "Not Found\n");
    return;
  }

  int depth = 1;
  const std::string depth_header = header_value(ctx.head, http::field::depth);
  if (iequals(depth_header, "0")) {
    depth = 0;
  } else if (iequals(depth_header, "1")) {
    depth = 1;
  } else {
    (void)response.send_text(http::status::forbidden, "Depth infinity is not supported\n");
    return;
  }

  PropRequest request;
  if (ctx.body.has_body()) {
    std::string body_text;
    if (!read_body_limited(ctx.body, body_text, kMaxControlBody)) {
      response.set_keep_alive(false);
      (void)response.send_text(http::status::bad_request, "Malformed body\n");
      return;
    }
    if (!parse_prop_request(body_text, request)) {
      (void)response.send_text(http::status::bad_request, "Malformed property request\n");
      return;
    }
  }

  response.result(http::status::multi_status);
  response.set("Content-Type", "application/xml; charset=\"utf-8\"");
  response.set("Transfer-Encoding", "chunked");
  if (!response.write_head()) {
    return;
  }
  (void)response.write_chunk("<D:multistatus xmlns:D=\"DAV:\">");

  const bool is_collection = target.is_root || S_ISDIR(target.info.st_mode);
  const std::string self_href = build_href(target.decoded_path, is_collection);
  emit_resource(response, self_href, target.leaf, target.info, is_collection, request);

  if (depth == 1 && is_collection) {
    Fd dir;
    if (target.is_root) {
      dir = Fd{fs_openat(target.parent.get(), ".", O_RDONLY | O_DIRECTORY | O_CLOEXEC, 0)};
    } else {
      dir = open_leaf(target.parent, target.leaf, O_RDONLY | O_DIRECTORY);
    }
    if (dir.valid()) {
      DirStream stream(dir.duplicate());
      std::string name;
      struct stat info {};
      while (stream.next(name, info)) {
        if (S_ISLNK(info.st_mode)) {
          continue;  // symlinks are never exposed or followed
        }
        const bool child_collection = S_ISDIR(info.st_mode);
        const std::string base = target.decoded_path == "/"
                                     ? "/" + name
                                     : target.decoded_path + "/" + name;
        emit_resource(response, build_href(base, child_collection), name, info, child_collection,
                      request);
      }
    }
  }

  (void)response.write_chunk("</D:multistatus>");
  (void)response.finish_chunked();
}

void handle_proppatch(DavContext& ctx, Response& response) {
  const Target target = resolve_path(ctx.root, std::string(ctx.head.target()));
  if (!target.ok()) {
    (void)response.send_text(status_for_path(target.status, false), "Error\n");
    return;
  }
  if (!target.exists) {
    (void)response.send_text(http::status::not_found, "Not Found\n");
    return;
  }

  std::string body_text;
  if (ctx.body.has_body()) {
    if (!read_body_limited(ctx.body, body_text, kMaxControlBody)) {
      response.set_keep_alive(false);
      (void)response.send_text(http::status::bad_request, "Malformed body\n");
      return;
    }
  }
  std::vector<std::string> names;
  collect_names(body_text, {"propertyupdate", "set", "remove", "prop"}, names);
  if (names.empty()) {
    (void)response.send_text(http::status::bad_request, "Malformed property update\n");
    return;
  }

  const bool is_collection = target.is_root || S_ISDIR(target.info.st_mode);
  std::string xml;
  xml.reserve(512);
  xml.append("<D:multistatus xmlns:D=\"DAV:\"><D:response><D:href>");
  xml.append(xml_escape(build_href(target.decoded_path, is_collection)));
  xml.append("</D:href><D:propstat><D:prop>");
  for (const std::string& name : names) {
    xml.append("<D:");
    xml.append(name);
    xml.append("/>");
  }
  xml.append("</D:prop><D:status>HTTP/1.1 403 Forbidden</D:status></D:propstat>");
  xml.append("</D:response></D:multistatus>");

  response.result(http::status::multi_status);
  response.set("Content-Type", "application/xml; charset=\"utf-8\"");
  response.set("Content-Length", std::to_string(xml.size()));
  if (!response.write_head()) {
    return;
  }
  (void)response.write(xml);
}

struct Destination {
  bool ok{false};
  bool host_mismatch{false};
  std::string path;
};

Destination parse_destination(std::string_view value, std::string_view host_header) {
  Destination result;
  if (value.empty()) {
    return result;
  }
  std::string_view rest = value;
  const std::size_t scheme = rest.find("://");
  if (scheme != std::string_view::npos) {
    rest.remove_prefix(scheme + 3);
    const std::size_t slash = rest.find('/');
    const std::string_view authority = slash == std::string_view::npos ? rest : rest.substr(0, slash);
    if (!authority.empty() && !host_header.empty() && !iequals(authority, host_header)) {
      result.host_mismatch = true;
      return result;
    }
    rest = slash == std::string_view::npos ? std::string_view("/") : rest.substr(slash);
  }
  if (rest.empty() || rest.front() != '/') {
    return result;
  }
  result.path.assign(rest);
  result.ok = true;
  return result;
}  // LCOV_EXCL_LINE

bool overwrite_allowed(const http::request_header<>& head) {
  const auto raw = head[http::field::overwrite];
  if (raw.empty()) {
    return true;
  }
  return !iequals(std::string_view(raw.data(), raw.size()), "F");
}

void handle_copy_move(DavContext& ctx, Response& response, bool move) {
  const Target source = resolve_path(ctx.root, std::string(ctx.head.target()));
  if (!source.ok()) {
    (void)response.send_text(status_for_path(source.status, false), "Error\n");
    return;
  }
  if (!source.exists) {
    (void)response.send_text(http::status::not_found, "Not Found\n");
    return;
  }
  if (ctx.body.has_body()) {
    response.set_keep_alive(false);
  }

  const std::string host = header_value(ctx.head, http::field::host);
  const Destination destination =
      parse_destination(std::string(header_value(ctx.head, http::field::destination)), host);
  if (destination.host_mismatch) {
    (void)response.send_text(http::status::bad_gateway, "Destination host mismatch\n");
    return;
  }
  if (!destination.ok) {
    (void)response.send_text(http::status::bad_request, "Missing or invalid Destination\n");
    return;
  }

  const Target target = resolve_path(ctx.root, destination.path);
  if (!target.ok()) {
    (void)response.send_text(status_for_path(target.status, true), "Error\n");
    return;
  }
  if (target.is_root) {
    (void)response.send_text(http::status::forbidden, "Destination is the root\n");
    return;
  }

  const bool source_is_collection = S_ISDIR(source.info.st_mode);
  if (source.decoded_path == target.decoded_path) {
    (void)response.send_text(http::status::forbidden, "Source and destination are identical\n");
    return;
  }
  if (source_is_collection &&
      target.decoded_path.compare(0, source.decoded_path.size(), source.decoded_path) == 0 &&
      target.decoded_path.size() > source.decoded_path.size() &&
      target.decoded_path[source.decoded_path.size()] == '/') {
    (void)response.send_text(http::status::forbidden, "Destination is inside the source\n");
    return;
  }
  const bool target_is_prefix =
      source.decoded_path.compare(0, target.decoded_path.size(), target.decoded_path) == 0;
  if (target.decoded_path.size() < source.decoded_path.size() && target_is_prefix &&
      source.decoded_path[target.decoded_path.size()] == '/') {
    (void)response.send_text(http::status::forbidden, "Destination is an ancestor of the source\n");
    return;
  }
  if (target.exists && !overwrite_allowed(ctx.head)) {
    (void)response.send_text(http::status::precondition_failed, "Destination exists\n");
    return;
  }

  const bool overwritten = target.exists;
  if (overwritten) {
    const int rc = remove_tree(target.parent, target.leaf);
    if (rc != 0) {
      (void)response.send_text(status_for_errno(rc, true), "Cannot replace destination\n");
      return;
    }
  }

  int failure = 0;
  if (move) {
    if (fs_renameat(source.parent.get(), source.leaf.c_str(), target.parent.get(),
                    target.leaf.c_str()) != 0) {
      if (errno == EXDEV) {
        failure = copy_tree(source.parent, source.leaf, target.parent, target.leaf, true);
        if (failure == 0) {
          failure = remove_tree(source.parent, source.leaf);
        }
      } else {
        failure = errno;
      }
    }
  } else {
    bool recursive = true;
    if (source_is_collection) {
      const std::string depth = header_value(ctx.head, http::field::depth);
      recursive = !iequals(depth, "0");
    }
    failure = copy_tree(source.parent, source.leaf, target.parent, target.leaf, recursive);
  }

  if (failure != 0) {
    (void)response.send_text(status_for_errno(failure, false), "Copy or move failed\n");
    return;
  }
  response.result(overwritten ? http::status::no_content : http::status::created);
  response.set("Content-Length", "0");
  (void)response.write_head();
}

}  // namespace

void handle_dav_request(DavContext& ctx, Response& response) {
  const std::string_view method = ctx.head.method_string();
  if (method == "OPTIONS") {
    handle_options(response);
  } else if (method == "GET") {
    handle_get(ctx, response, false);
  } else if (method == "HEAD") {
    handle_get(ctx, response, true);
  } else if (method == "PUT") {
    handle_put(ctx, response);
  } else if (method == "DELETE") {
    handle_delete(ctx, response);
  } else if (method == "MKCOL") {
    handle_mkcol(ctx, response);
  } else if (method == "PROPFIND") {
    handle_propfind(ctx, response);
  } else if (method == "PROPPATCH") {
    handle_proppatch(ctx, response);
  } else if (method == "COPY") {
    handle_copy_move(ctx, response, false);
  } else if (method == "MOVE") {
    handle_copy_move(ctx, response, true);
  } else {
    method_not_allowed(response);
  }
}

}  // namespace webdav
