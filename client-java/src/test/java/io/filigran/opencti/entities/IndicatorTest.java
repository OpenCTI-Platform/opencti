package io.filigran.opencti.entities;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.filigran.opencti.OpenCTIApiClient;
import okhttp3.mockwebserver.MockResponse;
import okhttp3.mockwebserver.MockWebServer;
import org.junit.jupiter.api.*;

import java.io.IOException;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.*;

/**
 * Unit tests for Indicator entity.
 */
@Tag("unit")
class IndicatorTest {

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
    @DisplayName("Should generate consistent STIX IDs based on pattern")
    void shouldGenerateConsistentStixIds() {
        String pattern = "[file:hashes.MD5 = 'd41d8cd98f00b204e9800998ecf8427e']";
        
        String id1 = Indicator.generateId(pattern);
        String id2 = Indicator.generateId(pattern);
        String id3 = Indicator.generateId("[ipv4-addr:value = '192.168.1.1']");
        
        assertThat(id1).isEqualTo(id2);
        assertThat(id1).isNotEqualTo(id3);
        assertThat(id1).startsWith("indicator--");
    }

    @Test
    @DisplayName("Should create indicator successfully")
    void shouldCreateIndicatorSuccessfully() throws Exception {
        Map<String, Object> responseData = Map.of(
            "data", Map.of(
                "indicatorAdd", Map.of(
                    "id", "indicator-123",
                    "standard_id", "indicator--uuid",
                    "entity_type", "Indicator",
                    "parent_types", List.of("Stix-Domain-Object")
                )
            )
        );
        
        mockWebServer.enqueue(new MockResponse()
            .setBody(objectMapper.writeValueAsString(responseData))
            .addHeader("Content-Type", "application/json"));
        
        Map<String, Object> result = client.getIndicator().create(
            "Test Indicator",
            "[file:hashes.MD5 = 'd41d8cd98f00b204e9800998ecf8427e']",
            "stix",
            "StixFile",
            "x_opencti_score", 75
        );
        
        assertThat(result).isNotNull();
        assertThat(result.get("id")).isEqualTo("indicator-123");
        assertThat(result.get("entity_type")).isEqualTo("Indicator");
    }

    @Test
    @DisplayName("Should normalize File to StixFile")
    void shouldNormalizeFileToStixFile() throws Exception {
        Map<String, Object> responseData = Map.of(
            "data", Map.of(
                "indicatorAdd", Map.of(
                    "id", "indicator-123",
                    "standard_id", "indicator--uuid",
                    "entity_type", "Indicator"
                )
            )
        );
        
        mockWebServer.enqueue(new MockResponse()
            .setBody(objectMapper.writeValueAsString(responseData))
            .addHeader("Content-Type", "application/json"));
        
        // Using "File" as main_observable_type - should be normalized to "StixFile"
        Map<String, Object> result = client.getIndicator().create(
            "Test",
            "[file:hashes.MD5 = 'abc']",
            "stix",
            "File"
        );
        
        assertThat(result).isNotNull();
    }

    @Test
    @DisplayName("Should return null when required parameters are missing")
    void shouldReturnNullWhenRequiredParametersAreMissing() {
        Map<String, Object> result = client.getIndicator().create("Test", null, "stix", "StixFile");
        assertThat(result).isNull();
        
        result = client.getIndicator().create("Test", "[pattern]", null, "StixFile");
        assertThat(result).isNull();
        
        result = client.getIndicator().create("Test", "[pattern]", "stix", null);
        assertThat(result).isNull();
    }

    @Test
    @DisplayName("Should list indicators with filters")
    void shouldListIndicatorsWithFilters() throws Exception {
        Map<String, Object> responseData = Map.of(
            "data", Map.of(
                "indicators", Map.of(
                    "edges", List.of(
                        Map.of("node", Map.of("id", "1", "name", "Indicator 1", "pattern", "[ip]")),
                        Map.of("node", Map.of("id", "2", "name", "Indicator 2", "pattern", "[file]"))
                    ),
                    "pageInfo", Map.of(
                        "hasNextPage", false,
                        "globalCount", 2
                    )
                )
            )
        );
        
        mockWebServer.enqueue(new MockResponse()
            .setBody(objectMapper.writeValueAsString(responseData))
            .addHeader("Content-Type", "application/json"));
        
        var result = client.getIndicator().list(null, null, 10, null, null, null);
        
        assertThat(result).hasSize(2);
        assertThat(result.get(0).get("name")).isEqualTo("Indicator 1");
    }

    @Test
    @DisplayName("Should read indicator by ID")
    void shouldReadIndicatorById() throws Exception {
        Map<String, Object> responseData = Map.of(
            "data", Map.of(
                "indicator", Map.of(
                    "id", "indicator-123",
                    "name", "Test Indicator",
                    "pattern", "[file:hashes.MD5 = 'abc']",
                    "pattern_type", "stix",
                    "x_opencti_main_observable_type", "StixFile",
                    "x_opencti_score", 75
                )
            )
        );
        
        mockWebServer.enqueue(new MockResponse()
            .setBody(objectMapper.writeValueAsString(responseData))
            .addHeader("Content-Type", "application/json"));
        
        Map<String, Object> result = client.getIndicator().read("indicator-123");
        
        assertThat(result).isNotNull();
        assertThat(result.get("name")).isEqualTo("Test Indicator");
        assertThat(result.get("x_opencti_score")).isEqualTo(75);
    }

    @Test
    @DisplayName("Should import indicator from STIX2")
    void shouldImportIndicatorFromStix2() throws Exception {
        Map<String, Object> responseData = Map.of(
            "data", Map.of(
                "indicatorAdd", Map.of(
                    "id", "indicator-123",
                    "standard_id", "indicator--uuid",
                    "entity_type", "Indicator"
                )
            )
        );
        
        mockWebServer.enqueue(new MockResponse()
            .setBody(objectMapper.writeValueAsString(responseData))
            .addHeader("Content-Type", "application/json"));
        
        Map<String, Object> stixObject = Map.of(
            "id", "indicator--uuid",
            "type", "indicator",
            "name", "Test Indicator",
            "pattern", "[file:hashes.MD5 = 'abc']",
            "pattern_type", "stix",
            "x_opencti_main_observable_type", "StixFile",
            "x_opencti_score", 80,
            "valid_from", "2021-01-01T00:00:00Z"
        );
        
        Map<String, Object> result = client.getIndicator().importFromStix2(stixObject, null, false);
        
        assertThat(result).isNotNull();
        assertThat(result.get("id")).isEqualTo("indicator-123");
    }
}

