package io.filigran.opencti.examples;

import io.filigran.opencti.OpenCTIApiClient;

import java.util.Map;

/**
 * Example demonstrating how to import a STIX bundle into OpenCTI.
 * 
 * To run this example:
 * 1. Set environment variables OPENCTI_API_URL and OPENCTI_API_TOKEN
 * 2. Run: mvn exec:java -Dexec.mainClass="io.filigran.opencti.examples.ImportStixBundleExample"
 */
public class ImportStixBundleExample {

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
        
        System.out.println("=== Import STIX Bundle Example ===\n");
        
        // Example STIX 2.1 bundle
        String stixBundle = """
            {
                "type": "bundle",
                "id": "bundle--example-001",
                "objects": [
                    {
                        "type": "malware",
                        "spec_version": "2.1",
                        "id": "malware--java-example-001",
                        "created": "2024-01-01T00:00:00.000Z",
                        "modified": "2024-01-01T00:00:00.000Z",
                        "name": "ExampleMalware from STIX Bundle",
                        "description": "This malware was imported via STIX bundle using Java client",
                        "malware_types": ["trojan"],
                        "is_family": false
                    },
                    {
                        "type": "indicator",
                        "spec_version": "2.1",
                        "id": "indicator--java-example-001",
                        "created": "2024-01-01T00:00:00.000Z",
                        "modified": "2024-01-01T00:00:00.000Z",
                        "name": "ExampleIndicator from STIX Bundle",
                        "description": "This indicator was imported via STIX bundle",
                        "pattern": "[file:hashes.SHA256 = 'aec070645fe53ee3b3763059376134f058cc337247c978add178b6ccdfb0019f']",
                        "pattern_type": "stix",
                        "valid_from": "2024-01-01T00:00:00.000Z",
                        "extensions": {
                            "extension-definition--ea279b3e-5c71-4632-ac08-831c66a786ba": {
                                "extension_type": "property-extension",
                                "main_observable_type": "StixFile",
                                "score": 85
                            }
                        }
                    },
                    {
                        "type": "relationship",
                        "spec_version": "2.1",
                        "id": "relationship--java-example-001",
                        "created": "2024-01-01T00:00:00.000Z",
                        "modified": "2024-01-01T00:00:00.000Z",
                        "relationship_type": "indicates",
                        "source_ref": "indicator--java-example-001",
                        "target_ref": "malware--java-example-001",
                        "description": "Indicator indicates malware"
                    }
                ]
            }
            """;
        
        System.out.println("1. Importing STIX bundle...");
        System.out.println("   Bundle contains: 1 malware, 1 indicator, 1 relationship");
        
        Map<String, Object> result = client.importBundle(stixBundle);
        System.out.println("   Import result: " + result);
        
        // Wait a bit for processing
        try {
            System.out.println("\n2. Waiting for processing...");
            Thread.sleep(5000);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
        
        // Verify import
        System.out.println("\n3. Verifying import...");
        
        // Try to read the malware
        Map<String, Object> malware = client.getMalware().read("malware--java-example-001");
        if (malware != null) {
            System.out.println("   Malware found: " + malware.get("name"));
        } else {
            System.out.println("   Malware not found yet (may still be processing)");
        }
        
        // Try to read the indicator
        Map<String, Object> indicator = client.getIndicator().read("indicator--java-example-001");
        if (indicator != null) {
            System.out.println("   Indicator found: " + indicator.get("name"));
        } else {
            System.out.println("   Indicator not found yet (may still be processing)");
        }
        
        System.out.println("\n=== Import example completed! ===");
    }
}

