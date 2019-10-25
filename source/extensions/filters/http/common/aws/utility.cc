#include "extensions/filters/http/common/aws/utility.h"

#include "common/common/fmt.h"
#include "common/common/utility.h"

#include "absl/strings/str_join.h"
#include "curl/curl.h"

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace Common {
namespace Aws {

std::map<std::string, std::string> Utility::canonicalizeHeaders(const Http::HeaderMap& headers) {
  std::map<std::string, std::string> out;
  headers.iterate(
      [](const Http::HeaderEntry& entry, void* context) -> Http::HeaderMap::Iterate {
        auto* map = static_cast<std::map<std::string, std::string>*>(context);
        // Skip empty headers
        if (entry.key().empty() || entry.value().empty()) {
          return Http::HeaderMap::Iterate::Continue;
        }
        // Pseudo-headers should not be canonicalized
        if (!entry.key().getStringView().empty() && entry.key().getStringView()[0] == ':') {
          return Http::HeaderMap::Iterate::Continue;
        }
        std::string value(entry.value().getStringView());
        // Remove leading, trailing, and deduplicate repeated ascii spaces
        absl::RemoveExtraAsciiWhitespace(&value);
        const auto iter = map->find(std::string(entry.key().getStringView()));
        // If the entry already exists, append the new value to the end
        if (iter != map->end()) {
          iter->second += fmt::format(",{}", value);
        } else {
          map->emplace(std::string(entry.key().getStringView()), value);
        }
        return Http::HeaderMap::Iterate::Continue;
      },
      &out);
  // The AWS SDK has a quirk where it removes "default ports" (80, 443) from the host headers
  // Additionally, we canonicalize the :authority header as "host"
  // TODO(lavignes): This may need to be tweaked to canonicalize :authority for HTTP/2 requests
  const auto* authority_header = headers.Host();
  if (authority_header != nullptr && !authority_header->value().empty()) {
    const auto& value = authority_header->value().getStringView();
    const auto parts = StringUtil::splitToken(value, ":");
    if (parts.size() > 1 && (parts[1] == "80" || parts[1] == "443")) {
      // Has default port, so use only the host part
      out.emplace(Http::Headers::get().HostLegacy.get(), std::string(parts[0]));
    } else {
      out.emplace(Http::Headers::get().HostLegacy.get(), std::string(value));
    }
  }
  return out;
}

std::string
Utility::createCanonicalRequest(absl::string_view method, absl::string_view path,
                                const std::map<std::string, std::string>& canonical_headers,
                                absl::string_view content_hash) {
  std::vector<absl::string_view> parts;
  parts.emplace_back(method);
  // don't include the query part of the path
  const auto path_part = StringUtil::cropRight(path, "?");
  parts.emplace_back(path_part.empty() ? "/" : path_part);
  const auto query_part = StringUtil::cropLeft(path, "?");
  // if query_part == path_part, then there is no query
  parts.emplace_back(query_part == path_part ? "" : query_part);
  std::vector<std::string> formatted_headers;
  formatted_headers.reserve(canonical_headers.size());
  for (const auto& header : canonical_headers) {
    formatted_headers.emplace_back(fmt::format("{}:{}", header.first, header.second));
    parts.emplace_back(formatted_headers.back());
  }
  // need an extra blank space after the canonical headers
  parts.emplace_back("");
  const auto signed_headers = Utility::joinCanonicalHeaderNames(canonical_headers);
  parts.emplace_back(signed_headers);
  parts.emplace_back(content_hash);
  return absl::StrJoin(parts, "\n");
}

std::string
Utility::joinCanonicalHeaderNames(const std::map<std::string, std::string>& canonical_headers) {
  return absl::StrJoin(canonical_headers, ";", [](auto* out, const auto& pair) {
    return absl::StrAppend(out, pair.first);
  });
}

std::string Utility::getSTSEndpoint(absl::string_view region) {
  if (region == "cn-northwest-1" || region == "cn-north-1") {
    return fmt::format("sts.{}.amazonaws.com.cn", region);
  }
  return fmt::format("sts.{}.amazonaws.com", region);
}

static size_t curlCallback(char* ptr, size_t, size_t nmemb, void* data) {
  auto buf = static_cast<std::string*>(data);
  buf->append(ptr, nmemb);
  return nmemb;
}

absl::optional<std::string> Utility::fetchMetadata(Http::Message& message) {
  // TODO(lavignes): Should remove this util in favor of custom client like
  // Envoy::Http::RestApiFetcher
  static const size_t MAX_RETRIES = 4;
  static const std::chrono::milliseconds RETRY_DELAY{1000};
  static const std::chrono::seconds TIMEOUT{5};
  CURL* const curl = curl_easy_init();
  RELEASE_ASSERT(curl != nullptr, "");
  const auto host = message.headers().Host()->value().getStringView();
  const auto path = message.headers().Path()->value().getStringView();
  const auto scheme = message.headers().Scheme()->value().getStringView();

  const std::string url = fmt::format("{}://{}{}", scheme, host, path);
  curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
  curl_easy_setopt(curl, CURLOPT_TIMEOUT, TIMEOUT.count());
  curl_easy_setopt(curl, CURLOPT_FAILONERROR, 1L);
  curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
  std::string buffer;
  curl_easy_setopt(curl, CURLOPT_WRITEDATA, &buffer);
  curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, curlCallback);

  struct curl_slist* headers = nullptr;
  message.headers().iterate(
      [](const Http::HeaderEntry& entry, void* context) -> Http::HeaderMap::Iterate {
        auto** headers = static_cast<struct curl_slist**>(context);
        // Skip pseudo-headers
        if (!entry.key().getStringView().empty() && entry.key().getStringView()[0] == ':') {
          return Http::HeaderMap::Iterate::Continue;
        }
        const std::string header =
            fmt::format("{}: {}", entry.key().getStringView(), entry.value().getStringView());
        *headers = curl_slist_append(*headers, header.c_str());
        return Http::HeaderMap::Iterate::Continue;
      },
      &headers);
  if (headers != nullptr) {
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
  }
  for (size_t retry = 0; retry < MAX_RETRIES; retry++) {
    const CURLcode res = curl_easy_perform(curl);
    if (res == CURLE_OK) {
      break;
    }
    ENVOY_LOG_MISC(debug, "Could not fetch AWS metadata: {}", curl_easy_strerror(res));
    buffer.clear();
    std::this_thread::sleep_for(RETRY_DELAY);
  }

  curl_easy_cleanup(curl);
  curl_slist_free_all(headers);
  return buffer.empty() ? absl::nullopt : absl::optional<std::string>(buffer);
}

} // namespace Aws
} // namespace Common
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy
