# OpenCTI client for Java

[![Website](https://img.shields.io/badge/website-opencti.io-blue.svg)](https://opencti.io)
[![Slack Status](https://img.shields.io/badge/slack-3K%2B%20members-4A154B)](https://community.filigran.io)

The official OpenCTI Java client helps developers to use the OpenCTI API by providing easy-to-use methods and utilities. This client is modeled after the Python client (pycti) and provides similar functionality for Java applications.

## Requirements

- Java 17 or higher
- Maven 3.6+

## Install

### Maven

Add the following dependency to your `pom.xml`:

```xml
<dependency>
    <groupId>io.filigran.opencti</groupId>
    <artifactId>opencti-client-java</artifactId>
    <version>6.9.6</version>
</dependency>
```

### Gradle

Add the following to your `build.gradle`:

```groovy
implementation 'io.filigran.opencti:opencti-client-java:6.9.6'
```

## Quick Start

### Basic Usage

```java
import io.filigran.opencti.OpenCTIApiClient;
import java.util.Map;
import java.util.List;

public class Example {
    public static void main(String[] args) {
        // Create client
        OpenCTIApiClient client = OpenCTIApiClient.builder()
            .url("http://localhost:4000")
            .token("your-api-token")
            .build();

        // Check health
        boolean healthy = client.healthCheck();
        System.out.println("OpenCTI is healthy: " + healthy);

        // Get platform version
        String version = client.getPlatformVersion();
        System.out.println("Platform version: " + version);

        // List malwares
        List<Map<String, Object>> malwares = client.getMalware().list(
            null,  // filters
            null,  // search
            10,    // first
            null,  // after
            "name", // orderBy
            "asc"   // orderMode
        );
        System.out.println("Found " + malwares.size() + " malwares");
    }
}
```

### Creating Entities

```java
// Create a malware
Map<String, Object> malware = client.getMalware().create(
    "WannaCry",
    "description", "A ransomware that encrypts files",
    "is_family", true,
    "malware_types", List.of("ransomware")
);
System.out.println("Created malware: " + malware.get("id"));

// Create an indicator
Map<String, Object> indicator = client.getIndicator().create(
    "WannaCry Hash",                                          // name
    "[file:hashes.MD5 = 'd41d8cd98f00b204e9800998ecf8427e']", // pattern
    "stix",                                                    // pattern_type
    "StixFile",                                               // main_observable_type
    "description", "MD5 hash of WannaCry sample",
    "x_opencti_score", 90
);
System.out.println("Created indicator: " + indicator.get("id"));
```

### Creating Relationships

```java
// Create a relationship between indicator and malware
Map<String, Object> relationship = client.getStixCoreRelationship().create(
    indicator.get("id").toString(),  // fromId
    malware.get("id").toString(),    // toId
    "indicates",                      // relationship_type
    "description", "Indicator for WannaCry malware",
    "confidence", 90
);
System.out.println("Created relationship: " + relationship.get("id"));
```

### Using Filters

```java
import io.filigran.opencti.model.FilterGroup;

// Simple equals filter
FilterGroup filter = FilterGroup.eq("name", "WannaCry");
List<Map<String, Object>> results = client.getMalware().list(filter, null, 10, null, null, null);

// Contains filter
FilterGroup searchFilter = FilterGroup.contains("name", "Wanna");
results = client.getMalware().list(searchFilter, null, 10, null, null, null);

// Complex filter with multiple conditions
FilterGroup complexFilter = FilterGroup.builder()
    .mode("and")
    .filters(List.of(
        FilterGroup.Filter.builder()
            .key("entity_type")
            .values(List.of("Malware"))
            .operator("eq")
            .build(),
        FilterGroup.Filter.builder()
            .key("is_family")
            .values(List.of("true"))
            .operator("eq")
            .build()
    ))
    .filterGroups(List.of())
    .build();
```

### Pagination

```java
import io.filigran.opencti.model.PaginatedResult;

// Get paginated results
PaginatedResult result = client.getMalware().list(
    null,   // filters
    null,   // search
    100,    // first (page size)
    null,   // after (cursor)
    "name", // orderBy
    "asc",  // orderMode
    true,   // withPagination
    false,  // withFiles
    null    // customAttributes
);

System.out.println("Total count: " + result.getGlobalCount());
System.out.println("Has next page: " + result.hasNextPage());
System.out.println("Entities in this page: " + result.getEntities().size());

// Get next page
if (result.hasNextPage()) {
    PaginatedResult nextPage = client.getMalware().list(
        null, null, 100, result.getEndCursor(), "name", "asc", true, false, null
    );
}

// Or get all results automatically
List<Map<String, Object>> allMalwares = client.getMalware().listAll(null);
```

### STIX Bundle Operations

```java
// Import a STIX bundle
String stixBundle = """
{
    "type": "bundle",
    "id": "bundle--xxx",
    "objects": [...]
}
""";
client.importBundle(stixBundle);

// Get STIX content of an entity
Map<String, Object> stixContent = client.getStixContent(malware.get("id").toString());
```

### File Upload

```java
// Upload a file
byte[] fileContent = Files.readAllBytes(Path.of("report.pdf"));
Map<String, Object> uploadResult = client.uploadFile(
    "report.pdf",
    fileContent,
    "application/pdf"
);
```

## Configuration Options

```java
OpenCTIApiClient client = OpenCTIApiClient.builder()
    .url("http://localhost:4000")           // Required: OpenCTI URL
    .token("your-api-token")                // Required: API token
    .sslVerify(true)                        // Verify SSL certificates (default: false)
    .requestTimeout(300)                     // Timeout in seconds (default: 300)
    .performHealthCheck(true)               // Check API on init (default: true)
    .customHeaders("X-Custom:value")        // Custom headers (format: "key:value;key:value")
    .provider("myapp/1.0.0")                // Provider for User-Agent header
    .bundleSendToQueue(true)                // Send bundles to queue (default: true)
    .proxy(new Proxy(...))                  // HTTP proxy configuration
    .build();
```

## Available Entity Operations

All entity classes provide the following common methods:

| Method | Description |
|--------|-------------|
| `list(...)` | List entities with optional filters, pagination |
| `listAll(...)` | Get all entities (handles pagination automatically) |
| `read(id)` | Read entity by ID |
| `read(filters)` | Read entity by filters |
| `create(...)` | Create new entity |
| `updateField(id, key, value)` | Update entity field |
| `delete(id)` | Delete entity |
| `addLabel(id, labelId)` | Add label to entity |
| `removeLabel(id, labelId)` | Remove label from entity |
| `addMarkingDefinition(id, markingId)` | Add marking definition |
| `removeMarkingDefinition(id, markingId)` | Remove marking definition |
| `addExternalReference(id, refId)` | Add external reference |
| `removeExternalReference(id, refId)` | Remove external reference |

### Supported Entities

- **Threat Intelligence**: `Malware`, `Indicator`, `AttackPattern`, `Campaign`, `IntrusionSet`, `ThreatActor`, `Tool`, `Vulnerability`
- **Observations**: `StixCyberObservable`
- **Analysis**: `Report`, `Note`, `Grouping`
- **Infrastructure**: `Infrastructure`, `CourseOfAction`
- **Context**: `Identity`, `Location`, `Incident`
- **Meta**: `Label`, `MarkingDefinition`, `KillChainPhase`, `ExternalReference`
- **Relationships**: `StixCoreRelationship`, `StixSightingRelationship`
- **Generic**: `StixDomainObject`, `StixCoreObject`, `Stix`

## Local Development

```bash
# Clone the repository
git clone https://github.com/OpenCTI-Platform/opencti.git
cd opencti/client-java

# Build the project
mvn clean install

# Run unit tests
mvn test

# Run all tests (including integration, requires running OpenCTI)
export OPENCTI_API_URL="http://localhost:4000"
export OPENCTI_API_TOKEN="your-api-token"
mvn verify -P integration-tests
```

## Tests

### Unit Tests

Unit tests run without external dependencies using MockWebServer:

```bash
mvn test -Dgroups=unit
```

### Integration Tests

Integration tests require a running OpenCTI instance:

```bash
export OPENCTI_API_URL="http://localhost:4000"
export OPENCTI_API_TOKEN="your-api-token"
mvn verify -P integration-tests
```

## Error Handling

```java
import io.filigran.opencti.exception.OpenCTIApiException;

try {
    Map<String, Object> malware = client.getMalware().read("invalid-id");
} catch (OpenCTIApiException e) {
    System.err.println("API Error: " + e.getMessage());
}
```

## Logging

The client uses SLF4J for logging. Add your preferred logging implementation:

```xml
<!-- Logback example -->
<dependency>
    <groupId>ch.qos.logback</groupId>
    <artifactId>logback-classic</artifactId>
    <version>1.4.14</version>
</dependency>
```

## About

OpenCTI is a product designed and developed by the company [Filigran](https://filigran.io).

<a href="https://filigran.io" alt="Filigran"><img src="https://github.com/OpenCTI-Platform/opencti/raw/master/.github/img/logo_filigran.png" width="300" /></a>

