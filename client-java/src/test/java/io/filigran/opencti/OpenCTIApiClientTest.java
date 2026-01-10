package io.filigran.opencti;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.filigran.opencti.exception.OpenCTIApiException;
import okhttp3.mockwebserver.MockResponse;
import okhttp3.mockwebserver.MockWebServer;
import okhttp3.mockwebserver.RecordedRequest;
import org.junit.jupiter.api.*;

import java.io.IOException;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.*;

/**
 * Unit tests for OpenCTIApiClient.
 */
@Tag("unit")
class OpenCTIApiClientTest {

    private MockWebServer mockWebServer;
    private OpenCTIApiClient client;
    private final ObjectMapper objectMapper = new ObjectMapper();

    @BeforeEach
    void setUp() throws IOException {
        mockWebServer = new MockWebServer();
        mockWebServer.start();
        
        client = OpenCTIApiClient.builder()
            .url(mockWebServer.url("").toString().replaceAll("/$", ""))
            .token("test-token")
            .performHealthCheck(false)
            .sslVerify(false)
            .build();
    }

    @AfterEach
    void tearDown() throws IOException {
        mockWebServer.shutdown();
    }

    @Test
    @DisplayName("Should throw exception when URL is missing")
    void shouldThrowExceptionWhenUrlIsMissing() {
        assertThatThrownBy(() -> OpenCTIApiClient.builder()
            .token("test-token")
            .performHealthCheck(false)
            .build())
            .isInstanceOf(IllegalArgumentException.class)
            .hasMessage("An URL must be set");
    }

    @Test
    @DisplayName("Should throw exception when token is missing")
    void shouldThrowExceptionWhenTokenIsMissing() {
        assertThatThrownBy(() -> OpenCTIApiClient.builder()
            .url("http://localhost:4000")
            .performHealthCheck(false)
            .build())
            .isInstanceOf(IllegalArgumentException.class)
            .hasMessage("A TOKEN must be set");
    }

    @Test
    @DisplayName("Should throw exception when token is 'ChangeMe'")
    void shouldThrowExceptionWhenTokenIsChangeMe() {
        assertThatThrownBy(() -> OpenCTIApiClient.builder()
            .url("http://localhost:4000")
            .token("ChangeMe")
            .performHealthCheck(false)
            .build())
            .isInstanceOf(IllegalArgumentException.class)
            .hasMessage("A TOKEN must be set");
    }

    @Test
    @DisplayName("Should throw exception for invalid provider format")
    void shouldThrowExceptionForInvalidProviderFormat() {
        assertThatThrownBy(() -> OpenCTIApiClient.builder()
            .url("http://localhost:4000")
            .token("test-token")
            .provider("invalid-format")
            .performHealthCheck(false)
            .build())
            .isInstanceOf(IllegalArgumentException.class)
            .hasMessageContaining("Provider format is incorrect");
    }

    @Test
    @DisplayName("Should accept valid provider format")
    void shouldAcceptValidProviderFormat() {
        assertThatCode(() -> OpenCTIApiClient.builder()
            .url(mockWebServer.url("").toString().replaceAll("/$", ""))
            .token("test-token")
            .provider("myapp/1.0.0")
            .performHealthCheck(false)
            .build())
            .doesNotThrowAnyException();
    }

    @Test
    @DisplayName("Should execute GraphQL query successfully")
    void shouldExecuteGraphQLQuerySuccessfully() throws Exception {
        Map<String, Object> responseData = Map.of(
            "data", Map.of(
                "about", Map.of("version", "6.9.6")
            )
        );
        
        mockWebServer.enqueue(new MockResponse()
            .setBody(objectMapper.writeValueAsString(responseData))
            .addHeader("Content-Type", "application/json"));
        
        Map<String, Object> result = client.query("""
            query {
                about {
                    version
                }
            }
            """);
        
        assertThat(result).containsKey("data");
        @SuppressWarnings("unchecked")
        Map<String, Object> data = (Map<String, Object>) result.get("data");
        assertThat(data).containsKey("about");
        
        RecordedRequest request = mockWebServer.takeRequest();
        assertThat(request.getHeader("Authorization")).isEqualTo("Bearer test-token");
        assertThat(request.getHeader("User-Agent")).startsWith("opencti-java/");
    }

    @Test
    @DisplayName("Should throw exception on GraphQL errors")
    void shouldThrowExceptionOnGraphQLErrors() throws Exception {
        Map<String, Object> errorResponse = Map.of(
            "errors", List.of(
                Map.of("name", "ValidationError", "message", "Invalid input")
            )
        );
        
        mockWebServer.enqueue(new MockResponse()
            .setBody(objectMapper.writeValueAsString(errorResponse))
            .addHeader("Content-Type", "application/json"));
        
        assertThatThrownBy(() -> client.query("query { test }"))
            .isInstanceOf(OpenCTIApiException.class)
            .hasMessageContaining("ValidationError");
    }

    @Test
    @DisplayName("Should throw exception on HTTP error")
    void shouldThrowExceptionOnHttpError() {
        mockWebServer.enqueue(new MockResponse()
            .setResponseCode(500)
            .setBody("Internal Server Error"));
        
        assertThatThrownBy(() -> client.query("query { test }"))
            .isInstanceOf(OpenCTIApiException.class)
            .hasMessageContaining("HTTP 500");
    }

    @Test
    @DisplayName("Should process multiple entities correctly")
    void shouldProcessMultipleEntitiesCorrectly() {
        Map<String, Object> data = Map.of(
            "edges", List.of(
                Map.of("node", Map.of("id", "1", "name", "Test 1")),
                Map.of("node", Map.of("id", "2", "name", "Test 2"))
            ),
            "pageInfo", Map.of(
                "hasNextPage", true,
                "endCursor", "cursor123",
                "globalCount", 10
            )
        );
        
        var result = client.processMultiple(data, true);
        
        assertThat(result.getEntities()).hasSize(2);
        assertThat(result.hasNextPage()).isTrue();
        assertThat(result.getEndCursor()).isEqualTo("cursor123");
        assertThat(result.getGlobalCount()).isEqualTo(10);
    }

    @Test
    @DisplayName("Should check not empty values correctly")
    void shouldCheckNotEmptyValuesCorrectly() {
        assertThat(client.notEmpty(null)).isFalse();
        assertThat(client.notEmpty("")).isFalse();
        assertThat(client.notEmpty("test")).isTrue();
        assertThat(client.notEmpty(List.of())).isFalse();
        assertThat(client.notEmpty(List.of("a"))).isTrue();
        assertThat(client.notEmpty(Map.of())).isFalse();
        assertThat(client.notEmpty(Map.of("a", "b"))).isTrue();
        assertThat(client.notEmpty(true)).isTrue();
        assertThat(client.notEmpty(false)).isTrue();
        assertThat(client.notEmpty(0)).isTrue();
        assertThat(client.notEmpty(123)).isTrue();
    }

    @Test
    @DisplayName("Should set headers correctly")
    void shouldSetHeadersCorrectly() throws Exception {
        Map<String, Object> responseData = Map.of("data", Map.of());
        
        mockWebServer.enqueue(new MockResponse()
            .setBody(objectMapper.writeValueAsString(responseData))
            .addHeader("Content-Type", "application/json"));
        
        client.setApplicantIdHeader("user-123");
        client.setPlaybookIdHeader("playbook-456");
        client.setDraftId("draft-789");
        
        client.query("query { test }");
        
        RecordedRequest request = mockWebServer.takeRequest();
        assertThat(request.getHeader("opencti-applicant-id")).isEqualTo("user-123");
        assertThat(request.getHeader("opencti-playbook-id")).isEqualTo("playbook-456");
        assertThat(request.getHeader("opencti-draft-id")).isEqualTo("draft-789");
    }

    @Test
    @DisplayName("Should get request headers with hidden token")
    void shouldGetRequestHeadersWithHiddenToken() {
        Map<String, String> headers = client.getRequestHeaders(true);
        
        assertThat(headers.get("Authorization")).isEqualTo("*****");
    }

    @Test
    @DisplayName("Should get request headers with visible token")
    void shouldGetRequestHeadersWithVisibleToken() {
        Map<String, String> headers = client.getRequestHeaders(false);
        
        assertThat(headers.get("Authorization")).isEqualTo("Bearer test-token");
    }

    @Test
    @DisplayName("Should perform health check")
    void shouldPerformHealthCheck() throws Exception {
        Map<String, Object> responseData = Map.of(
            "data", Map.of(
                "about", Map.of("version", "6.9.6")
            )
        );
        
        mockWebServer.enqueue(new MockResponse()
            .setBody(objectMapper.writeValueAsString(responseData))
            .addHeader("Content-Type", "application/json"));
        
        boolean healthy = client.healthCheck();
        
        assertThat(healthy).isTrue();
    }

    @Test
    @DisplayName("Should return false for failed health check")
    void shouldReturnFalseForFailedHealthCheck() {
        mockWebServer.enqueue(new MockResponse()
            .setResponseCode(500)
            .setBody("Internal Server Error"));
        
        boolean healthy = client.healthCheck();
        
        assertThat(healthy).isFalse();
    }

    @Test
    @DisplayName("Should parse custom headers correctly")
    void shouldParseCustomHeadersCorrectly() throws Exception {
        OpenCTIApiClient clientWithHeaders = OpenCTIApiClient.builder()
            .url(mockWebServer.url("").toString().replaceAll("/$", ""))
            .token("test-token")
            .customHeaders("X-Custom-Header:value1;X-Another:value2")
            .performHealthCheck(false)
            .build();

        Map<String, Object> responseData = Map.of("data", Map.of());
        mockWebServer.enqueue(new MockResponse()
            .setBody(objectMapper.writeValueAsString(responseData))
            .addHeader("Content-Type", "application/json"));
        
        clientWithHeaders.query("query { test }");
        
        RecordedRequest request = mockWebServer.takeRequest();
        assertThat(request.getHeader("X-Custom-Header")).isEqualTo("value1");
        assertThat(request.getHeader("X-Another")).isEqualTo("value2");
    }
}

