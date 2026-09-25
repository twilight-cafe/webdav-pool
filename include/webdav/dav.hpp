#pragma once

#include <string_view>

#include "webdav/config.hpp"
#include "webdav/fsutil.hpp"
#include "webdav/http.hpp"

namespace webdav {

inline constexpr std::string_view kAllowMethods =
    "OPTIONS, GET, HEAD, PUT, DELETE, MKCOL, PROPFIND, PROPPATCH, COPY, MOVE";

struct DavContext {
  TcpSocket& socket;
  const http::request_header<>& head;
  BodyReader& body;
  const Fd& root;
  const User& user;
};

// Handles one authenticated request, writing the complete response.
void handle_dav_request(DavContext& ctx, Response& response);

}  // namespace webdav
