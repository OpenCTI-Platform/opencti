package io.filigran.opencti.integration;

import io.filigran.opencti.OpenCTIApiClient;
import io.filigran.opencti.model.FilterGroup;
import org.junit.jupiter.api.*;

import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.*;
import static org.junit.jupiter.api.Assumptions.*;

/**
 * Integration tests for entity CRUD operations.
 * 
 * These tests require a running OpenCTI instance.
 * Set environment variables:
 * - OPENCTI_API_URL (default: http://localhost:4000)
 * - OPENCTI_API_TOKEN (required)
 */
@Tag("integration")
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
class EntityCrudIT {

    private static OpenCTIApiClient client;
    private static String createdMalwareId;
    private static String createdIndicatorId;
    private static String createdRelationshipId;

    @BeforeAll
    static void setUpClass() {
        String apiUrl = System.getenv("OPENCTI_API_URL");
        if (apiUrl == null) {
            apiUrl = "http://localhost:4000";
        }
        
        String apiToken = System.getenv("OPENCTI_API_TOKEN");
        assumeTrue(apiToken != null && !apiToken.isEmpty(), 
            "OPENCTI_API_TOKEN environment variable must be set");
        
        client = OpenCTIApiClient.builder()
            .url(apiUrl)
            .token(apiToken)
            .sslVerify(false)
            .performHealthCheck(true)
            .build();
    }

    @Test
    @Order(1)
    @DisplayName("Should perform health check successfully")
    void shouldPerformHealthCheck() {
        boolean healthy = client.healthCheck();
        assertThat(healthy).isTrue();
    }

    @Test
    @Order(2)
    @DisplayName("Should get platform version")
    void shouldGetPlatformVersion() {
        String version = client.getPlatformVersion();
        assertThat(version).isNotNull();
        assertThat(version).matches("\\d+\\.\\d+\\.\\d+.*");
    }

    @Test
    @Order(10)
    @DisplayName("Should create malware")
    void shouldCreateMalware() {
        Map<String, Object> malware = client.getMalware().create(
            "Test Malware - Java Client IT",
            "description", "A test malware created by Java client integration tests",
            "is_family", true,
            "malware_types", List.of("ransomware", "trojan")
        );
        
        assertThat(malware).isNotNull();
        assertThat(malware.get("id")).isNotNull();
        assertThat(malware.get("standard_id")).isNotNull();
        assertThat(malware.get("entity_type")).isEqualTo("Malware");
        
        createdMalwareId = (String) malware.get("id");
    }

    @Test
    @Order(11)
    @DisplayName("Should read malware by ID")
    void shouldReadMalwareById() {
        assumeTrue(createdMalwareId != null, "Malware must be created first");
        
        Map<String, Object> malware = client.getMalware().read(createdMalwareId);
        
        assertThat(malware).isNotNull();
        assertThat(malware.get("id")).isEqualTo(createdMalwareId);
        assertThat(malware.get("name")).isEqualTo("Test Malware - Java Client IT");
        assertThat(malware.get("is_family")).isEqualTo(true);
    }

    @Test
    @Order(12)
    @DisplayName("Should update malware field")
    void shouldUpdateMalwareField() {
        assumeTrue(createdMalwareId != null, "Malware must be created first");
        
        Map<String, Object> updated = client.getMalware().updateField(
            createdMalwareId, 
            "description", 
            "Updated description by Java client"
        );
        
        assertThat(updated).isNotNull();
        
        // Verify update
        Map<String, Object> malware = client.getMalware().read(createdMalwareId);
        assertThat(malware.get("description")).isEqualTo("Updated description by Java client");
    }

    @Test
    @Order(13)
    @DisplayName("Should list malwares with filter")
    void shouldListMalwaresWithFilter() {
        assumeTrue(createdMalwareId != null, "Malware must be created first");
        
        FilterGroup filter = FilterGroup.eq("name", "Test Malware - Java Client IT");
        
        List<Map<String, Object>> malwares = client.getMalware().list(filter, null, 10, null, null, null);
        
        assertThat(malwares).isNotEmpty();
        assertThat(malwares).anyMatch(m -> m.get("id").equals(createdMalwareId));
    }

    @Test
    @Order(20)
    @DisplayName("Should create indicator")
    void shouldCreateIndicator() {
        Map<String, Object> indicator = client.getIndicator().create(
            "Test Indicator - Java Client IT",
            "[file:hashes.MD5 = 'd41d8cd98f00b204e9800998ecf8427e']",
            "stix",
            "StixFile",
            "description", "A test indicator created by Java client integration tests",
            "x_opencti_score", 75
        );
        
        assertThat(indicator).isNotNull();
        assertThat(indicator.get("id")).isNotNull();
        assertThat(indicator.get("standard_id")).isNotNull();
        assertThat(indicator.get("entity_type")).isEqualTo("Indicator");
        
        createdIndicatorId = (String) indicator.get("id");
    }

    @Test
    @Order(21)
    @DisplayName("Should read indicator by ID")
    void shouldReadIndicatorById() {
        assumeTrue(createdIndicatorId != null, "Indicator must be created first");
        
        Map<String, Object> indicator = client.getIndicator().read(createdIndicatorId);
        
        assertThat(indicator).isNotNull();
        assertThat(indicator.get("id")).isEqualTo(createdIndicatorId);
        assertThat(indicator.get("name")).isEqualTo("Test Indicator - Java Client IT");
    }

    @Test
    @Order(30)
    @DisplayName("Should create relationship between malware and indicator")
    void shouldCreateRelationship() {
        assumeTrue(createdMalwareId != null, "Malware must be created first");
        assumeTrue(createdIndicatorId != null, "Indicator must be created first");
        
        Map<String, Object> relationship = client.getStixCoreRelationship().create(
            createdIndicatorId,
            createdMalwareId,
            "indicates",
            "description", "Test relationship created by Java client"
        );
        
        assertThat(relationship).isNotNull();
        assertThat(relationship.get("id")).isNotNull();
        
        createdRelationshipId = (String) relationship.get("id");
    }

    @Test
    @Order(31)
    @DisplayName("Should list relationships")
    void shouldListRelationships() {
        assumeTrue(createdRelationshipId != null, "Relationship must be created first");
        
        List<Map<String, Object>> relationships = client.getStixCoreRelationship().list(
            null, createdIndicatorId, null, "indicates", 10, null
        );
        
        assertThat(relationships).isNotEmpty();
        assertThat(relationships).anyMatch(r -> r.get("id").equals(createdRelationshipId));
    }

    @Test
    @Order(90)
    @DisplayName("Should delete relationship")
    void shouldDeleteRelationship() {
        assumeTrue(createdRelationshipId != null, "Relationship must be created first");
        
        client.getStixCoreRelationship().delete(createdRelationshipId);
        
        // Verify deletion
        Map<String, Object> relationship = client.getStixCoreRelationship().read(createdRelationshipId);
        assertThat(relationship).isNull();
    }

    @Test
    @Order(91)
    @DisplayName("Should delete indicator")
    void shouldDeleteIndicator() {
        assumeTrue(createdIndicatorId != null, "Indicator must be created first");
        
        client.getIndicator().delete(createdIndicatorId);
        
        // Verify deletion
        Map<String, Object> indicator = client.getIndicator().read(createdIndicatorId);
        assertThat(indicator).isNull();
    }

    @Test
    @Order(92)
    @DisplayName("Should delete malware")
    void shouldDeleteMalware() {
        assumeTrue(createdMalwareId != null, "Malware must be created first");
        
        client.getMalware().delete(createdMalwareId);
        
        // Verify deletion
        Map<String, Object> malware = client.getMalware().read(createdMalwareId);
        assertThat(malware).isNull();
    }
}

