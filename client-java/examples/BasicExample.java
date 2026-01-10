package io.filigran.opencti.examples;

import io.filigran.opencti.OpenCTIApiClient;
import io.filigran.opencti.model.FilterGroup;

import java.util.List;
import java.util.Map;

/**
 * Basic example demonstrating the usage of the OpenCTI Java Client.
 * 
 * To run this example:
 * 1. Set environment variables OPENCTI_API_URL and OPENCTI_API_TOKEN
 * 2. Run: mvn exec:java -Dexec.mainClass="io.filigran.opencti.examples.BasicExample"
 */
public class BasicExample {

    public static void main(String[] args) {
        // Get configuration from environment
        String apiUrl = System.getenv("OPENCTI_API_URL");
        String apiToken = System.getenv("OPENCTI_API_TOKEN");
        
        if (apiUrl == null || apiToken == null) {
            System.err.println("Please set OPENCTI_API_URL and OPENCTI_API_TOKEN environment variables");
            System.exit(1);
        }
        
        // Create the client
        OpenCTIApiClient client = OpenCTIApiClient.builder()
            .url(apiUrl)
            .token(apiToken)
            .sslVerify(false)
            .build();
        
        System.out.println("=== OpenCTI Java Client Example ===\n");
        
        // 1. Health check
        System.out.println("1. Performing health check...");
        boolean healthy = client.healthCheck();
        System.out.println("   OpenCTI is healthy: " + healthy);
        
        // 2. Get platform version
        System.out.println("\n2. Getting platform version...");
        String version = client.getPlatformVersion();
        System.out.println("   Platform version: " + version);
        
        // 3. Create a malware
        System.out.println("\n3. Creating a malware...");
        Map<String, Object> malware = client.getMalware().create(
            "Test Malware - Java Example",
            "description", "A test malware created by Java client example",
            "is_family", true,
            "malware_types", List.of("ransomware")
        );
        String malwareId = (String) malware.get("id");
        System.out.println("   Created malware: " + malwareId);
        
        // 4. Read the malware back
        System.out.println("\n4. Reading the malware...");
        Map<String, Object> readMalware = client.getMalware().read(malwareId);
        System.out.println("   Name: " + readMalware.get("name"));
        System.out.println("   Description: " + readMalware.get("description"));
        System.out.println("   Is Family: " + readMalware.get("is_family"));
        
        // 5. Create an indicator
        System.out.println("\n5. Creating an indicator...");
        Map<String, Object> indicator = client.getIndicator().create(
            "Test Indicator - Java Example",
            "[file:hashes.MD5 = 'd41d8cd98f00b204e9800998ecf8427e']",
            "stix",
            "StixFile",
            "x_opencti_score", 75,
            "description", "Test indicator from Java example"
        );
        String indicatorId = (String) indicator.get("id");
        System.out.println("   Created indicator: " + indicatorId);
        
        // 6. Create a relationship
        System.out.println("\n6. Creating a relationship (indicator -> malware)...");
        Map<String, Object> relationship = client.getStixCoreRelationship().create(
            indicatorId,
            malwareId,
            "indicates",
            "description", "Test relationship from Java example",
            "confidence", 80
        );
        String relationshipId = (String) relationship.get("id");
        System.out.println("   Created relationship: " + relationshipId);
        
        // 7. List relationships
        System.out.println("\n7. Listing relationships from indicator...");
        List<Map<String, Object>> relationships = client.getStixCoreRelationship().list(
            null, indicatorId, null, null, 10, null
        );
        System.out.println("   Found " + relationships.size() + " relationship(s)");
        
        // 8. Create a label
        System.out.println("\n8. Creating a label...");
        Map<String, Object> label = client.getLabel().create(
            "java-test-label",
            "color", "#FF5733"
        );
        String labelId = (String) label.get("id");
        System.out.println("   Created label: " + labelId);
        
        // 9. Add label to malware
        System.out.println("\n9. Adding label to malware...");
        client.getMalware().addLabel(malwareId, labelId);
        System.out.println("   Label added successfully");
        
        // 10. List all malwares with filter
        System.out.println("\n10. Listing malwares with filter...");
        FilterGroup filter = FilterGroup.contains("name", "Java Example");
        List<Map<String, Object>> filteredMalwares = client.getMalware().list(
            filter, null, 10, null, "name", "asc"
        );
        System.out.println("   Found " + filteredMalwares.size() + " malware(s) matching filter");
        
        // Cleanup
        System.out.println("\n11. Cleaning up...");
        
        // Delete relationship first
        client.getStixCoreRelationship().delete(relationshipId);
        System.out.println("   Deleted relationship");
        
        // Delete indicator
        client.getIndicator().delete(indicatorId);
        System.out.println("   Deleted indicator");
        
        // Remove label and delete malware
        client.getMalware().removeLabel(malwareId, labelId);
        client.getMalware().delete(malwareId);
        System.out.println("   Deleted malware");
        
        // Delete label
        client.getLabel().delete(labelId);
        System.out.println("   Deleted label");
        
        System.out.println("\n=== Example completed successfully! ===");
    }
}

