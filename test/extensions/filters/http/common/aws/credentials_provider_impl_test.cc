#include "extensions/filters/http/common/aws/credentials_provider_impl.h"

#include "test/extensions/filters/http/common/aws/mocks.h"
#include "test/mocks/api/mocks.h"
#include "test/mocks/event/mocks.h"
#include "test/test_common/environment.h"
#include "test/test_common/simulated_time_system.h"

using testing::_;
using testing::InSequence;
using testing::NiceMock;
using testing::Ref;
using testing::Return;

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace Common {
namespace Aws {

class EvironmentCredentialsProviderTest : public testing::Test {
public:
  ~EvironmentCredentialsProviderTest() override {
    TestEnvironment::unsetEnvVar("AWS_ACCESS_KEY_ID");
    TestEnvironment::unsetEnvVar("AWS_SECRET_ACCESS_KEY");
    TestEnvironment::unsetEnvVar("AWS_SESSION_TOKEN");
  }

  EnvironmentCredentialsProvider provider_;
};

TEST_F(EvironmentCredentialsProviderTest, AllEnvironmentVars) {
  TestEnvironment::setEnvVar("AWS_ACCESS_KEY_ID", "akid", 1);
  TestEnvironment::setEnvVar("AWS_SECRET_ACCESS_KEY", "secret", 1);
  TestEnvironment::setEnvVar("AWS_SESSION_TOKEN", "token", 1);
  const auto credentials = provider_.getCredentials();
  EXPECT_EQ("akid", credentials.accessKeyId().value());
  EXPECT_EQ("secret", credentials.secretAccessKey().value());
  EXPECT_EQ("token", credentials.sessionToken().value());
}

TEST_F(EvironmentCredentialsProviderTest, NoEnvironmentVars) {
  const auto credentials = provider_.getCredentials();
  EXPECT_FALSE(credentials.accessKeyId().has_value());
  EXPECT_FALSE(credentials.secretAccessKey().has_value());
  EXPECT_FALSE(credentials.sessionToken().has_value());
}

TEST_F(EvironmentCredentialsProviderTest, MissingAccessKeyId) {
  TestEnvironment::setEnvVar("AWS_SECRET_ACCESS_KEY", "secret", 1);
  const auto credentials = provider_.getCredentials();
  EXPECT_FALSE(credentials.accessKeyId().has_value());
  EXPECT_FALSE(credentials.secretAccessKey().has_value());
  EXPECT_FALSE(credentials.sessionToken().has_value());
}

TEST_F(EvironmentCredentialsProviderTest, NoSessionToken) {
  TestEnvironment::setEnvVar("AWS_ACCESS_KEY_ID", "akid", 1);
  TestEnvironment::setEnvVar("AWS_SECRET_ACCESS_KEY", "secret", 1);
  const auto credentials = provider_.getCredentials();
  EXPECT_EQ("akid", credentials.accessKeyId().value());
  EXPECT_EQ("secret", credentials.secretAccessKey().value());
  EXPECT_FALSE(credentials.sessionToken().has_value());
}

class MessageMatcher : public testing::MatcherInterface<Http::Message&> {
public:
  explicit MessageMatcher(const Http::TestHeaderMapImpl& expected_headers)
      : expected_headers_(expected_headers) {}

  bool MatchAndExplain(Http::Message& message,
                       testing::MatchResultListener* result_listener) const override {
    const bool equal = TestUtility::headerMapEqualIgnoreOrder(message.headers(), expected_headers_);
    if (!equal) {
      *result_listener << "\n"
                       << TestUtility::addLeftAndRightPadding("Expected header map:") << "\n"
                       << expected_headers_
                       << TestUtility::addLeftAndRightPadding("is not equal to actual header map:")
                       << "\n"
                       << message.headers()
                       << TestUtility::addLeftAndRightPadding("") // line full of padding
                       << "\n";
    }
    return equal;
  }

  void DescribeTo(::std::ostream* os) const override { *os << "Message matches"; }

  void DescribeNegationTo(::std::ostream* os) const override { *os << "Message does not match"; }

private:
  const Http::TestHeaderMapImpl expected_headers_;
};

testing::Matcher<Http::Message&> MessageMatches(const Http::TestHeaderMapImpl& expected_headers) {
  return testing::MakeMatcher(new MessageMatcher(expected_headers));
}

class InstanceProfileCredentialsProviderTest : public testing::Test {
public:
  InstanceProfileCredentialsProviderTest()
      : api_(Api::createApiForTest(time_system_)),
        provider_(*api_, [this](Http::Message& message) -> absl::optional<std::string> {
          return this->fetcher_.fetch(message);
        }) {}

  void expectCredentialListing(const absl::optional<std::string>& listing) {
    Http::TestHeaderMapImpl headers{{":path", "/latest/meta-data/iam/security-credentials"},
                                    {":authority", "169.254.169.254:80"},
                                    {":scheme", "http"},
                                    {":method", "GET"}};
    EXPECT_CALL(fetcher_, fetch(MessageMatches(headers))).WillOnce(Return(listing));
  }

  void expectDocument(const absl::optional<std::string>& document) {
    Http::TestHeaderMapImpl headers{{":path", "/latest/meta-data/iam/security-credentials/doc1"},
                                    {":authority", "169.254.169.254:80"},
                                    {":scheme", "http"},
                                    {":method", "GET"}};
    EXPECT_CALL(fetcher_, fetch(MessageMatches(headers))).WillOnce(Return(document));
  }

  Event::SimulatedTimeSystem time_system_;
  Api::ApiPtr api_;
  NiceMock<MockMetadataFetcher> fetcher_;
  InstanceProfileCredentialsProvider provider_;
};

TEST_F(InstanceProfileCredentialsProviderTest, FailedCredentialListing) {
  expectCredentialListing(absl::optional<std::string>());
  const auto credentials = provider_.getCredentials();
  EXPECT_FALSE(credentials.accessKeyId().has_value());
  EXPECT_FALSE(credentials.secretAccessKey().has_value());
  EXPECT_FALSE(credentials.sessionToken().has_value());
}

TEST_F(InstanceProfileCredentialsProviderTest, EmptyCredentialListing) {
  expectCredentialListing("");
  const auto credentials = provider_.getCredentials();
  EXPECT_FALSE(credentials.accessKeyId().has_value());
  EXPECT_FALSE(credentials.secretAccessKey().has_value());
  EXPECT_FALSE(credentials.sessionToken().has_value());
}

TEST_F(InstanceProfileCredentialsProviderTest, MissingDocument) {
  expectCredentialListing("doc1\ndoc2\ndoc3");
  expectDocument(absl::optional<std::string>());
  const auto credentials = provider_.getCredentials();
  EXPECT_FALSE(credentials.accessKeyId().has_value());
  EXPECT_FALSE(credentials.secretAccessKey().has_value());
  EXPECT_FALSE(credentials.sessionToken().has_value());
}

TEST_F(InstanceProfileCredentialsProviderTest, MalformedDocumenet) {
  expectCredentialListing("doc1");
  expectDocument(R"EOF(
not json
)EOF");
  const auto credentials = provider_.getCredentials();
  EXPECT_FALSE(credentials.accessKeyId().has_value());
  EXPECT_FALSE(credentials.secretAccessKey().has_value());
  EXPECT_FALSE(credentials.sessionToken().has_value());
}

TEST_F(InstanceProfileCredentialsProviderTest, EmptyValues) {
  expectCredentialListing("doc1");
  expectDocument(R"EOF(
{
  "AccessKeyId": "",
  "SecretAccessKey": "",
  "Token": ""
}
)EOF");
  const auto credentials = provider_.getCredentials();
  EXPECT_FALSE(credentials.accessKeyId().has_value());
  EXPECT_FALSE(credentials.secretAccessKey().has_value());
  EXPECT_FALSE(credentials.sessionToken().has_value());
}

TEST_F(InstanceProfileCredentialsProviderTest, FullCachedCredentials) {
  expectCredentialListing("doc1");
  expectDocument(R"EOF(
{
  "AccessKeyId": "akid",
  "SecretAccessKey": "secret",
  "Token": "token"
}
)EOF");
  const auto credentials = provider_.getCredentials();
  EXPECT_EQ("akid", credentials.accessKeyId().value());
  EXPECT_EQ("secret", credentials.secretAccessKey().value());
  EXPECT_EQ("token", credentials.sessionToken().value());
  const auto cached_credentials = provider_.getCredentials();
  EXPECT_EQ("akid", cached_credentials.accessKeyId().value());
  EXPECT_EQ("secret", cached_credentials.secretAccessKey().value());
  EXPECT_EQ("token", cached_credentials.sessionToken().value());
}

TEST_F(InstanceProfileCredentialsProviderTest, CredentialExpiration) {
  InSequence sequence;
  expectCredentialListing("doc1");
  expectDocument(R"EOF(
{
  "AccessKeyId": "akid",
  "SecretAccessKey": "secret",
  "Token": "token"
}
)EOF");
  const auto credentials = provider_.getCredentials();
  EXPECT_EQ("akid", credentials.accessKeyId().value());
  EXPECT_EQ("secret", credentials.secretAccessKey().value());
  EXPECT_EQ("token", credentials.sessionToken().value());
  time_system_.sleep(std::chrono::hours(2));
  expectCredentialListing("doc1");
  expectDocument(R"EOF(
{
  "AccessKeyId": "new_akid",
  "SecretAccessKey": "new_secret",
  "Token": "new_token"
}
)EOF");
  const auto new_credentials = provider_.getCredentials();
  EXPECT_EQ("new_akid", new_credentials.accessKeyId().value());
  EXPECT_EQ("new_secret", new_credentials.secretAccessKey().value());
  EXPECT_EQ("new_token", new_credentials.sessionToken().value());
}

class TaskRoleCredentialsProviderTest : public testing::Test {
public:
  TaskRoleCredentialsProviderTest()
      : api_(Api::createApiForTest(time_system_)),
        provider_(
            *api_,
            [this](Http::Message& message) -> absl::optional<std::string> {
              return this->fetcher_.fetch(message);
            },
            "169.254.170.2:80/path/to/doc", "auth_token") {
    // Tue Jan  2 03:04:05 UTC 2018
    time_system_.setSystemTime(std::chrono::milliseconds(1514862245000));
  }

  void expectDocument(const absl::optional<std::string>& document) {
    Http::TestHeaderMapImpl headers = {{":path", "/path/to/doc"},
                                       {":authority", "169.254.170.2:80"},
                                       {":scheme", "http"},
                                       {":method", "GET"},
                                       {"authorization", "auth_token"}};
    EXPECT_CALL(fetcher_, fetch(MessageMatches(headers))).WillOnce(Return(document));
  }

  Event::SimulatedTimeSystem time_system_;
  Api::ApiPtr api_;
  NiceMock<MockMetadataFetcher> fetcher_;
  TaskRoleCredentialsProvider provider_;
};

TEST_F(TaskRoleCredentialsProviderTest, FailedFetchingDocument) {
  expectDocument(absl::optional<std::string>());
  const auto credentials = provider_.getCredentials();
  EXPECT_FALSE(credentials.accessKeyId().has_value());
  EXPECT_FALSE(credentials.secretAccessKey().has_value());
  EXPECT_FALSE(credentials.sessionToken().has_value());
}

TEST_F(TaskRoleCredentialsProviderTest, MalformedDocumenet) {
  expectDocument(R"EOF(
not json
)EOF");
  const auto credentials = provider_.getCredentials();
  EXPECT_FALSE(credentials.accessKeyId().has_value());
  EXPECT_FALSE(credentials.secretAccessKey().has_value());
  EXPECT_FALSE(credentials.sessionToken().has_value());
}

TEST_F(TaskRoleCredentialsProviderTest, EmptyValues) {
  expectDocument(R"EOF(
{
  "AccessKeyId": "",
  "SecretAccessKey": "",
  "Token": "",
  "Expiration": ""
}
)EOF");
  const auto credentials = provider_.getCredentials();
  EXPECT_FALSE(credentials.accessKeyId().has_value());
  EXPECT_FALSE(credentials.secretAccessKey().has_value());
  EXPECT_FALSE(credentials.sessionToken().has_value());
}

TEST_F(TaskRoleCredentialsProviderTest, FullCachedCredentials) {
  expectDocument(R"EOF(
{
  "AccessKeyId": "akid",
  "SecretAccessKey": "secret",
  "Token": "token",
  "Expiration": "20180102T030500Z"
}
)EOF");
  const auto credentials = provider_.getCredentials();
  EXPECT_EQ("akid", credentials.accessKeyId().value());
  EXPECT_EQ("secret", credentials.secretAccessKey().value());
  EXPECT_EQ("token", credentials.sessionToken().value());
  const auto cached_credentials = provider_.getCredentials();
  EXPECT_EQ("akid", cached_credentials.accessKeyId().value());
  EXPECT_EQ("secret", cached_credentials.secretAccessKey().value());
  EXPECT_EQ("token", cached_credentials.sessionToken().value());
}

TEST_F(TaskRoleCredentialsProviderTest, NormalCredentialExpiration) {
  InSequence sequence;
  expectDocument(R"EOF(
{
  "AccessKeyId": "akid",
  "SecretAccessKey": "secret",
  "Token": "token",
  "Expiration": "20190102T030405Z"
}
)EOF");
  const auto credentials = provider_.getCredentials();
  EXPECT_EQ("akid", credentials.accessKeyId().value());
  EXPECT_EQ("secret", credentials.secretAccessKey().value());
  EXPECT_EQ("token", credentials.sessionToken().value());
  time_system_.sleep(std::chrono::hours(2));
  expectDocument(R"EOF(
{
  "AccessKeyId": "new_akid",
  "SecretAccessKey": "new_secret",
  "Token": "new_token",
  "Expiration": "20190102T030405Z"
}
)EOF");
  const auto cached_credentials = provider_.getCredentials();
  EXPECT_EQ("new_akid", cached_credentials.accessKeyId().value());
  EXPECT_EQ("new_secret", cached_credentials.secretAccessKey().value());
  EXPECT_EQ("new_token", cached_credentials.sessionToken().value());
}

TEST_F(TaskRoleCredentialsProviderTest, TimestampCredentialExpiration) {
  InSequence sequence;
  expectDocument(R"EOF(
{
  "AccessKeyId": "akid",
  "SecretAccessKey": "secret",
  "Token": "token",
  "Expiration": "20180102T030405Z"
}
)EOF");
  const auto credentials = provider_.getCredentials();
  EXPECT_EQ("akid", credentials.accessKeyId().value());
  EXPECT_EQ("secret", credentials.secretAccessKey().value());
  EXPECT_EQ("token", credentials.sessionToken().value());
  expectDocument(R"EOF(
{
  "AccessKeyId": "new_akid",
  "SecretAccessKey": "new_secret",
  "Token": "new_token",
  "Expiration": "20190102T030405Z"
}
)EOF");
  const auto cached_credentials = provider_.getCredentials();
  EXPECT_EQ("new_akid", cached_credentials.accessKeyId().value());
  EXPECT_EQ("new_secret", cached_credentials.secretAccessKey().value());
  EXPECT_EQ("new_token", cached_credentials.sessionToken().value());
}

class WebIdentityCredentialsProviderTest : public testing::Test {
public:
  WebIdentityCredentialsProviderTest()
      : api_(Api::createApiForTest(time_system_)),
        provider_(
            *api_,
            [this](Http::Message& message) -> absl::optional<std::string> {
              return this->fetcher_.fetch(message);
            },
            TestEnvironment::writeStringToFileForTest("web_token_file", "web_token"),
            "sts.region.amazonaws.com", "aws:iam::123456789012:role/arn", "role-session-name") {
    // Tue Jan  2 03:04:05 UTC 2018
    time_system_.setSystemTime(std::chrono::milliseconds(1514862245000));
  }

  void expectDocument(const absl::optional<std::string>& document) {
    Http::TestHeaderMapImpl headers = {{":path",
                                        "/?Action=AssumeRoleWithWebIdentity"
                                        "&Version=2011-06-15&RoleSessionName=role-session-name"
                                        "&RoleArn=aws:iam::123456789012:role/arn"
                                        "&WebIdentityToken=web_token"},
                                       {":authority", "sts.region.amazonaws.com"},
                                       {":scheme", "https"},
                                       {":method", "GET"}};
    EXPECT_CALL(fetcher_, fetch(MessageMatches(headers))).WillOnce(Return(document));
  }

  Event::SimulatedTimeSystem time_system_;
  Api::ApiPtr api_;
  NiceMock<MockMetadataFetcher> fetcher_;
  WebIdentityCredentialsProvider provider_;
};

TEST_F(WebIdentityCredentialsProviderTest, FailedFetchingDocument) {
  expectDocument(absl::optional<std::string>());
  const auto credentials = provider_.getCredentials();
  EXPECT_FALSE(credentials.accessKeyId().has_value());
  EXPECT_FALSE(credentials.secretAccessKey().has_value());
  EXPECT_FALSE(credentials.sessionToken().has_value());
}

TEST_F(WebIdentityCredentialsProviderTest, MalformedDocumenet) {
  expectDocument(R"EOF(
not xml
)EOF");
  const auto credentials = provider_.getCredentials();
  EXPECT_FALSE(credentials.accessKeyId().has_value());
  EXPECT_FALSE(credentials.secretAccessKey().has_value());
  EXPECT_FALSE(credentials.sessionToken().has_value());
}

TEST_F(WebIdentityCredentialsProviderTest, UnexpectedResponse) {
  expectDocument(R"EOF(
<AssumeRoleWithWebIdentityResponse>
  <UnexpectedResponse>
  </UnexpectedResponse>
</AssumeRoleWithWebIdentityResponse>
)EOF");
  const auto credentials = provider_.getCredentials();
  EXPECT_FALSE(credentials.accessKeyId().has_value());
  EXPECT_FALSE(credentials.secretAccessKey().has_value());
  EXPECT_FALSE(credentials.sessionToken().has_value());
}

TEST_F(WebIdentityCredentialsProviderTest, NoCredentials) {
  expectDocument(R"EOF(
<AssumeRoleWithWebIdentityResponse>
  <AssumeRoleWithWebIdentityResult>
  </AssumeRoleWithWebIdentityResult>
</AssumeRoleWithWebIdentityResponse>
)EOF");
  const auto credentials = provider_.getCredentials();
  EXPECT_FALSE(credentials.accessKeyId().has_value());
  EXPECT_FALSE(credentials.secretAccessKey().has_value());
  EXPECT_FALSE(credentials.sessionToken().has_value());
}

TEST_F(WebIdentityCredentialsProviderTest, EmptyCredentials) {
  expectDocument(R"EOF(
<AssumeRoleWithWebIdentityResponse>
  <AssumeRoleWithWebIdentityResult>
    <Credentials>
    </Credentials>
  </AssumeRoleWithWebIdentityResult>
</AssumeRoleWithWebIdentityResponse>
)EOF");
  const auto credentials = provider_.getCredentials();
  EXPECT_FALSE(credentials.accessKeyId().has_value());
  EXPECT_FALSE(credentials.secretAccessKey().has_value());
  EXPECT_FALSE(credentials.sessionToken().has_value());
}

TEST_F(WebIdentityCredentialsProviderTest, FullCachedCredentials) {
  expectDocument(R"EOF(
<AssumeRoleWithWebIdentityResponse>
  <AssumeRoleWithWebIdentityResult>
    <Credentials>
      <AccessKeyId>akid</AccessKeyId>
      <SecretAccessKey>secret</SecretAccessKey>
      <SessionToken>token</SessionToken>
      <Expiration>2018-01-02T03:05:00Z</Expiration>
    </Credentials>
  </AssumeRoleWithWebIdentityResult>
</AssumeRoleWithWebIdentityResponse>
)EOF");
  const auto credentials = provider_.getCredentials();
  EXPECT_EQ("akid", credentials.accessKeyId().value());
  EXPECT_EQ("secret", credentials.secretAccessKey().value());
  EXPECT_EQ("token", credentials.sessionToken().value());
  const auto cached_credentials = provider_.getCredentials();
  EXPECT_EQ("akid", cached_credentials.accessKeyId().value());
  EXPECT_EQ("secret", cached_credentials.secretAccessKey().value());
  EXPECT_EQ("token", cached_credentials.sessionToken().value());
}

TEST_F(WebIdentityCredentialsProviderTest, NormalCredentialExpiration) {
  InSequence sequence;
  expectDocument(R"EOF(
<AssumeRoleWithWebIdentityResponse>
  <AssumeRoleWithWebIdentityResult>
    <Credentials>
      <AccessKeyId>akid</AccessKeyId>
      <SecretAccessKey>secret</SecretAccessKey>
      <SessionToken>token</SessionToken>
      <Expiration>2018-01-02T03:04:05Z</Expiration>
    </Credentials>
  </AssumeRoleWithWebIdentityResult>
</AssumeRoleWithWebIdentityResponse>
)EOF");
  const auto credentials = provider_.getCredentials();
  EXPECT_EQ("akid", credentials.accessKeyId().value());
  EXPECT_EQ("secret", credentials.secretAccessKey().value());
  EXPECT_EQ("token", credentials.sessionToken().value());
  time_system_.sleep(std::chrono::hours(2));
  expectDocument(R"EOF(
<AssumeRoleWithWebIdentityResponse>
  <AssumeRoleWithWebIdentityResult>
    <Credentials>
      <AccessKeyId>new_akid</AccessKeyId>
      <SecretAccessKey>new_secret</SecretAccessKey>
      <SessionToken>new_token</SessionToken>
      <Expiration>2019-01-02T03:05:00Z</Expiration>
    </Credentials>
  </AssumeRoleWithWebIdentityResult>
</AssumeRoleWithWebIdentityResponse>
)EOF");
  const auto cached_credentials = provider_.getCredentials();
  EXPECT_EQ("new_akid", cached_credentials.accessKeyId().value());
  EXPECT_EQ("new_secret", cached_credentials.secretAccessKey().value());
  EXPECT_EQ("new_token", cached_credentials.sessionToken().value());
}

TEST_F(WebIdentityCredentialsProviderTest, TimestampCredentialExpiration) {
  InSequence sequence;
  expectDocument(R"EOF(
<AssumeRoleWithWebIdentityResponse>
  <AssumeRoleWithWebIdentityResult>
    <Credentials>
      <AccessKeyId>akid</AccessKeyId>
      <SecretAccessKey>secret</SecretAccessKey>
      <SessionToken>token</SessionToken>
      <Expiration>2018-01-02T03:04:05Z</Expiration>
    </Credentials>
  </AssumeRoleWithWebIdentityResult>
</AssumeRoleWithWebIdentityResponse>
)EOF");
  const auto credentials = provider_.getCredentials();
  EXPECT_EQ("akid", credentials.accessKeyId().value());
  EXPECT_EQ("secret", credentials.secretAccessKey().value());
  EXPECT_EQ("token", credentials.sessionToken().value());
  expectDocument(R"EOF(
<AssumeRoleWithWebIdentityResponse>
  <AssumeRoleWithWebIdentityResult>
    <Credentials>
      <AccessKeyId>new_akid</AccessKeyId>
      <SecretAccessKey>new_secret</SecretAccessKey>
      <SessionToken>new_token</SessionToken>
      <Expiration>2019-01-02T03:04:05Z</Expiration>
    </Credentials>
  </AssumeRoleWithWebIdentityResult>
</AssumeRoleWithWebIdentityResponse>
)EOF");
  const auto cached_credentials = provider_.getCredentials();
  EXPECT_EQ("new_akid", cached_credentials.accessKeyId().value());
  EXPECT_EQ("new_secret", cached_credentials.secretAccessKey().value());
  EXPECT_EQ("new_token", cached_credentials.sessionToken().value());
}

class DefaultCredentialsProviderChainTest : public testing::Test {
public:
  DefaultCredentialsProviderChainTest() : api_(Api::createApiForTest(time_system_)) {
    TestEnvironment::setEnvVar("AWS_WEB_IDENTITY_TOKEN_FILE", "/path/to/web_token", 1);
    TestEnvironment::setEnvVar("AWS_ROLE_ARN", "aws:iam::123456789012:role/arn", 1);
    TestEnvironment::setEnvVar("AWS_ROLE_SESSION_NAME", "role-session-name", 1);

    EXPECT_CALL(factories_, createEnvironmentCredentialsProvider());
    EXPECT_CALL(factories_, createWebIdentityCredentialsProvider(
                                Ref(*api_), _, "/path/to/web_token", "sts.region.amazonaws.com",
                                "aws:iam::123456789012:role/arn", "role-session-name"));
  }

  ~DefaultCredentialsProviderChainTest() override {
    TestEnvironment::unsetEnvVar("AWS_CONTAINER_CREDENTIALS_RELATIVE_URI");
    TestEnvironment::unsetEnvVar("AWS_CONTAINER_CREDENTIALS_FULL_URI");
    TestEnvironment::unsetEnvVar("AWS_CONTAINER_AUTHORIZATION_TOKEN");
    TestEnvironment::unsetEnvVar("AWS_EC2_METADATA_DISABLED");
    TestEnvironment::unsetEnvVar("AWS_WEB_IDENTITY_TOKEN_FILE");
    TestEnvironment::unsetEnvVar("AWS_ROLE_ARN");
    TestEnvironment::unsetEnvVar("AWS_ROLE_SESSION_NAME");
  }

  class MockCredentialsProviderChainFactories : public CredentialsProviderChainFactories {
  public:
    MOCK_CONST_METHOD0(createEnvironmentCredentialsProvider, CredentialsProviderSharedPtr());
    MOCK_CONST_METHOD6(createWebIdentityCredentialsProvider,
                       CredentialsProviderSharedPtr(
                           Api::Api&, const MetadataCredentialsProviderBase::MetadataFetcher&,
                           absl::string_view, absl::string_view, absl::string_view,
                           absl::string_view));
    MOCK_CONST_METHOD4(createTaskRoleCredentialsProviderMock,
                       CredentialsProviderSharedPtr(
                           Api::Api&, const MetadataCredentialsProviderBase::MetadataFetcher&,
                           const std::string&, const std::string&));
    MOCK_CONST_METHOD2(createInstanceProfileCredentialsProvider,
                       CredentialsProviderSharedPtr(
                           Api::Api&,
                           const MetadataCredentialsProviderBase::MetadataFetcher& fetcher));

    CredentialsProviderSharedPtr createTaskRoleCredentialsProvider(
        Api::Api& api, const MetadataCredentialsProviderBase::MetadataFetcher& metadata_fetcher,
        const std::string& credential_uri, const std::string& authorization_token) const override {
      return createTaskRoleCredentialsProviderMock(api, metadata_fetcher, credential_uri,
                                                   authorization_token);
    }
  };

  Event::SimulatedTimeSystem time_system_;
  Api::ApiPtr api_;
  NiceMock<MockCredentialsProviderChainFactories> factories_;
};

TEST_F(DefaultCredentialsProviderChainTest, NoEnvironmentVars) {
  EXPECT_CALL(factories_, createInstanceProfileCredentialsProvider(Ref(*api_), _));
  DefaultCredentialsProviderChain chain(*api_, "region", DummyMetadataFetcher(), factories_);
}

TEST_F(DefaultCredentialsProviderChainTest, MetadataDisabled) {
  TestEnvironment::setEnvVar("AWS_EC2_METADATA_DISABLED", "true", 1);
  EXPECT_CALL(factories_, createInstanceProfileCredentialsProvider(Ref(*api_), _)).Times(0);
  DefaultCredentialsProviderChain chain(*api_, "region", DummyMetadataFetcher(), factories_);
}

TEST_F(DefaultCredentialsProviderChainTest, MetadataNotDisabled) {
  TestEnvironment::setEnvVar("AWS_EC2_METADATA_DISABLED", "false", 1);
  EXPECT_CALL(factories_, createInstanceProfileCredentialsProvider(Ref(*api_), _));
  DefaultCredentialsProviderChain chain(*api_, "region", DummyMetadataFetcher(), factories_);
}

TEST_F(DefaultCredentialsProviderChainTest, RelativeUri) {
  TestEnvironment::setEnvVar("AWS_CONTAINER_CREDENTIALS_RELATIVE_URI", "/path/to/creds", 1);
  EXPECT_CALL(factories_, createTaskRoleCredentialsProviderMock(
                              Ref(*api_), _, "169.254.170.2:80/path/to/creds", ""));
  DefaultCredentialsProviderChain chain(*api_, "region", DummyMetadataFetcher(), factories_);
}

TEST_F(DefaultCredentialsProviderChainTest, FullUriNoAuthorizationToken) {
  TestEnvironment::setEnvVar("AWS_CONTAINER_CREDENTIALS_FULL_URI", "http://host/path/to/creds", 1);
  EXPECT_CALL(factories_, createTaskRoleCredentialsProviderMock(Ref(*api_), _,
                                                                "http://host/path/to/creds", ""));
  DefaultCredentialsProviderChain chain(*api_, "region", DummyMetadataFetcher(), factories_);
}

TEST_F(DefaultCredentialsProviderChainTest, FullUriWithAuthorizationToken) {
  TestEnvironment::setEnvVar("AWS_CONTAINER_CREDENTIALS_FULL_URI", "http://host/path/to/creds", 1);
  TestEnvironment::setEnvVar("AWS_CONTAINER_AUTHORIZATION_TOKEN", "auth_token", 1);
  EXPECT_CALL(factories_, createTaskRoleCredentialsProviderMock(
                              Ref(*api_), _, "http://host/path/to/creds", "auth_token"));
  DefaultCredentialsProviderChain chain(*api_, "region", DummyMetadataFetcher(), factories_);
}

TEST(CredentialsProviderChainTest, getCredentials_noCredentials) {
  auto mock_provider1 = std::make_shared<MockCredentialsProvider>();
  auto mock_provider2 = std::make_shared<MockCredentialsProvider>();

  EXPECT_CALL(*mock_provider1, getCredentials()).Times(1);
  EXPECT_CALL(*mock_provider2, getCredentials()).Times(1);

  CredentialsProviderChain chain;
  chain.add(mock_provider1);
  chain.add(mock_provider2);

  const Credentials creds = chain.getCredentials();
  EXPECT_EQ(Credentials(), creds);
}

TEST(CredentialsProviderChainTest, getCredentials_firstProviderReturns) {
  auto mock_provider1 = std::make_shared<MockCredentialsProvider>();
  auto mock_provider2 = std::make_shared<MockCredentialsProvider>();

  const Credentials creds("access_key", "secret_key");

  EXPECT_CALL(*mock_provider1, getCredentials()).WillOnce(Return(creds));
  EXPECT_CALL(*mock_provider2, getCredentials()).Times(0);

  CredentialsProviderChain chain;
  chain.add(mock_provider1);
  chain.add(mock_provider2);

  const Credentials ret_creds = chain.getCredentials();
  EXPECT_EQ(creds, ret_creds);
}

TEST(CredentialsProviderChainTest, getCredentials_secondProviderReturns) {
  auto mock_provider1 = std::make_shared<MockCredentialsProvider>();
  auto mock_provider2 = std::make_shared<MockCredentialsProvider>();

  const Credentials creds("access_key", "secret_key");

  EXPECT_CALL(*mock_provider1, getCredentials()).Times(1);
  EXPECT_CALL(*mock_provider2, getCredentials()).WillOnce(Return(creds));

  CredentialsProviderChain chain;
  chain.add(mock_provider1);
  chain.add(mock_provider2);

  const Credentials ret_creds = chain.getCredentials();
  EXPECT_EQ(creds, ret_creds);
}

} // namespace Aws
} // namespace Common
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy
