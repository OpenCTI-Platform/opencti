package io.filigran.opencti;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import io.filigran.opencti.api.*;
import io.filigran.opencti.entities.*;
import io.filigran.opencti.exception.OpenCTIApiException;
import io.filigran.opencti.model.*;
import lombok.Getter;
import lombok.extern.slf4j.Slf4j;
import okhttp3.*;
import org.apache.commons.lang3.StringUtils;

import javax.net.ssl.*;
import java.io.IOException;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.util.*;
import java.util.concurrent.TimeUnit;
import java.util.regex.Pattern;

/**
 * Main API client for OpenCTI.
 * <p>
 * This is the primary entry point for interacting with the OpenCTI platform.
 * It provides access to all entity operations, utilities, and STIX2 support.
 * </p>
 *
 * <h2>Example usage:</h2>
 * <pre>{@code
 * OpenCTIApiClient client = OpenCTIApiClient.builder()
 *     .url("http://localhost:4000")
 *     .token("your-api-token")
 *     .build();
 *
 * // List malware
 * List<Map<String, Object>> malwares = client.getMalware().list();
 *
 * // Create an indicator
 * Map<String, Object> indicator = client.getIndicator().create(
 *     "name", "Test Indicator",
 *     "pattern", "[file:hashes.MD5 = 'd41d8cd98f00b204e9800998ecf8427e']",
 *     "pattern_type", "stix",
 *     "x_opencti_main_observable_type", "StixFile"
 * );
 * }</pre>
 *
 * @author Filigran Team
 * @since 6.9.6
 */
@Slf4j
public class OpenCTIApiClient {

    private static final String VERSION = "6.9.6";
    private static final MediaType JSON_MEDIA_TYPE = MediaType.parse("application/json; charset=utf-8");
    private static final Pattern PROVIDER_PATTERN = Pattern.compile("^[A-Za-z]+/\\d+(?:\\.\\d+){0,2}$");

    private final String apiUrl;
    @Getter
    private final String apiToken;
    private final OkHttpClient httpClient;
    private final ObjectMapper objectMapper;
    private final Map<String, String> requestHeaders;
    private final boolean bundleSendToQueue;

    @Getter
    private String draftId;

    // API modules
    @Getter
    private final OpenCTIApiWork work;
    @Getter
    private final OpenCTIApiConnector connector;
    @Getter
    private final OpenCTIApiTrash trash;
    @Getter
    private final OpenCTIApiDraft draft;

    // Entity handlers
    @Getter
    private final Malware malware;
    @Getter
    private final Indicator indicator;
    @Getter
    private final AttackPattern attackPattern;
    @Getter
    private final Campaign campaign;
    @Getter
    private final CourseOfAction courseOfAction;
    @Getter
    private final Identity identity;
    @Getter
    private final Incident incident;
    @Getter
    private final Infrastructure infrastructure;
    @Getter
    private final IntrusionSet intrusionSet;
    @Getter
    private final Location location;
    @Getter
    private final ThreatActor threatActor;
    @Getter
    private final Tool tool;
    @Getter
    private final Vulnerability vulnerability;
    @Getter
    private final Report report;
    @Getter
    private final Note note;
    @Getter
    private final Grouping grouping;
    @Getter
    private final ExternalReference externalReference;
    @Getter
    private final Label label;
    @Getter
    private final MarkingDefinition markingDefinition;
    @Getter
    private final KillChainPhase killChainPhase;
    @Getter
    private final StixCoreRelationship stixCoreRelationship;
    @Getter
    private final StixSightingRelationship stixSightingRelationship;
    @Getter
    private final StixCyberObservable stixCyberObservable;
    @Getter
    private final StixDomainObject stixDomainObject;
    @Getter
    private final StixCoreObject stixCoreObject;
    @Getter
    private final Stix stix;

    private OpenCTIApiClient(Builder builder) {
        // Validate configuration
        if (StringUtils.isBlank(builder.url)) {
            throw new IllegalArgumentException("An URL must be set");
        }
        if (StringUtils.isBlank(builder.token) || "ChangeMe".equals(builder.token)) {
            throw new IllegalArgumentException("A TOKEN must be set");
        }
        if (builder.provider != null && !PROVIDER_PATTERN.matcher(builder.provider).matches()) {
            throw new IllegalArgumentException(
                "Provider format is incorrect: format has to be {provider}/{provider_version}, e.g. client/4.5, company_name/1.4.6..."
            );
        }

        this.apiUrl = builder.url + "/graphql";
        this.apiToken = builder.token;
        this.bundleSendToQueue = builder.bundleSendToQueue;
        this.draftId = "";

        // Initialize ObjectMapper
        this.objectMapper = new ObjectMapper();
        this.objectMapper.registerModule(new JavaTimeModule());
        this.objectMapper.configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);
        this.objectMapper.configure(SerializationFeature.WRITE_DATES_AS_TIMESTAMPS, false);

        // Build request headers
        this.requestHeaders = new HashMap<>();
        String userAgent = "opencti-java/" + VERSION;
        if (builder.provider != null) {
            userAgent += " " + builder.provider;
        }
        this.requestHeaders.put("User-Agent", userAgent);
        this.requestHeaders.put("Authorization", "Bearer " + builder.token);
        
        // Add custom headers
        if (StringUtils.isNotBlank(builder.customHeaders)) {
            parseCustomHeaders(builder.customHeaders);
        }

        // Build HTTP client
        this.httpClient = buildHttpClient(builder);

        // Initialize API modules
        this.work = new OpenCTIApiWork(this);
        this.connector = new OpenCTIApiConnector(this);
        this.trash = new OpenCTIApiTrash(this);
        this.draft = new OpenCTIApiDraft(this);

        // Initialize entity handlers
        this.malware = new Malware(this);
        this.indicator = new Indicator(this);
        this.attackPattern = new AttackPattern(this);
        this.campaign = new Campaign(this);
        this.courseOfAction = new CourseOfAction(this);
        this.identity = new Identity(this);
        this.incident = new Incident(this);
        this.infrastructure = new Infrastructure(this);
        this.intrusionSet = new IntrusionSet(this);
        this.location = new Location(this);
        this.threatActor = new ThreatActor(this);
        this.tool = new Tool(this);
        this.vulnerability = new Vulnerability(this);
        this.report = new Report(this);
        this.note = new Note(this);
        this.grouping = new Grouping(this);
        this.externalReference = new ExternalReference(this);
        this.label = new Label(this);
        this.markingDefinition = new MarkingDefinition(this);
        this.killChainPhase = new KillChainPhase(this);
        this.stixCoreRelationship = new StixCoreRelationship(this);
        this.stixSightingRelationship = new StixSightingRelationship(this);
        this.stixCyberObservable = new StixCyberObservable(this);
        this.stixDomainObject = new StixDomainObject(this);
        this.stixCoreObject = new StixCoreObject(this);
        this.stix = new Stix(this);

        // Perform health check if enabled
        if (builder.performHealthCheck && !healthCheck()) {
            throw new OpenCTIApiException(
                "OpenCTI API is not reachable. Waiting for OpenCTI API to start or check your configuration..."
            );
        }
    }

    /**
     * Creates a new builder for OpenCTIApiClient.
     *
     * @return a new Builder instance
     */
    public static Builder builder() {
        return new Builder();
    }

    /**
     * Parse custom headers from string format "header01:value;header02:value"
     */
    private void parseCustomHeaders(String customHeaders) {
        for (String headerPair : customHeaders.strip().split(";")) {
            if (StringUtils.isNotBlank(headerPair)) {
                String[] parts = headerPair.split(":", 2);
                if (parts.length == 2) {
                    requestHeaders.put(parts[0].strip(), parts[1].strip());
                } else {
                    log.warn("Ignored invalid header pair: {}", headerPair);
                }
            }
        }
    }

    /**
     * Build the OkHttp client with appropriate configuration
     */
    private OkHttpClient buildHttpClient(Builder builder) {
        OkHttpClient.Builder httpBuilder = new OkHttpClient.Builder()
            .connectTimeout(builder.requestTimeout, TimeUnit.SECONDS)
            .readTimeout(builder.requestTimeout, TimeUnit.SECONDS)
            .writeTimeout(builder.requestTimeout, TimeUnit.SECONDS);

        // Configure SSL if verification is disabled
        if (!builder.sslVerify) {
            try {
                TrustManager[] trustAllCerts = new TrustManager[]{
                    new X509TrustManager() {
                        @Override
                        public void checkClientTrusted(X509Certificate[] chain, String authType) {}
                        @Override
                        public void checkServerTrusted(X509Certificate[] chain, String authType) {}
                        @Override
                        public X509Certificate[] getAcceptedIssuers() { return new X509Certificate[0]; }
                    }
                };

                SSLContext sslContext = SSLContext.getInstance("TLS");
                sslContext.init(null, trustAllCerts, new SecureRandom());
                
                httpBuilder.sslSocketFactory(sslContext.getSocketFactory(), (X509TrustManager) trustAllCerts[0]);
                httpBuilder.hostnameVerifier((hostname, session) -> true);
            } catch (Exception e) {
                log.warn("Failed to configure SSL trust all", e);
            }
        }

        // Configure proxy if provided
        if (builder.proxy != null) {
            httpBuilder.proxy(builder.proxy);
        }

        return httpBuilder.build();
    }

    /**
     * Execute a GraphQL query against the OpenCTI API.
     *
     * @param query the GraphQL query string
     * @return the response data
     * @throws OpenCTIApiException if the query fails
     */
    public Map<String, Object> query(String query) {
        return query(query, Collections.emptyMap());
    }

    /**
     * Execute a GraphQL query against the OpenCTI API.
     *
     * @param query the GraphQL query string
     * @param variables the query variables
     * @return the response data
     * @throws OpenCTIApiException if the query fails
     */
    public Map<String, Object> query(String query, Map<String, Object> variables) {
        return query(query, variables, false);
    }

    /**
     * Execute a GraphQL query against the OpenCTI API.
     *
     * @param query the GraphQL query string
     * @param variables the query variables
     * @param disableImpersonate whether to disable impersonation
     * @return the response data
     * @throws OpenCTIApiException if the query fails
     */
    @SuppressWarnings("unchecked")
    public Map<String, Object> query(String query, Map<String, Object> variables, boolean disableImpersonate) {
        try {
            // Build request body
            Map<String, Object> body = new HashMap<>();
            body.put("query", query);
            body.put("variables", variables != null ? variables : Collections.emptyMap());
            
            String jsonBody = objectMapper.writeValueAsString(body);
            RequestBody requestBody = RequestBody.create(jsonBody, JSON_MEDIA_TYPE);

            // Build headers
            Headers.Builder headersBuilder = new Headers.Builder();
            for (Map.Entry<String, String> header : requestHeaders.entrySet()) {
                if (disableImpersonate && "opencti-applicant-id".equals(header.getKey())) {
                    continue;
                }
                headersBuilder.add(header.getKey(), header.getValue());
            }
            if (StringUtils.isNotBlank(draftId)) {
                headersBuilder.add("opencti-draft-id", draftId);
            }

            Request request = new Request.Builder()
                .url(apiUrl)
                .headers(headersBuilder.build())
                .post(requestBody)
                .build();

            try (Response response = httpClient.newCall(request).execute()) {
                String responseBody = response.body() != null ? response.body().string() : "";

                if (!response.isSuccessful()) {
                    throw new OpenCTIApiException("HTTP " + response.code() + ": " + responseBody);
                }

                Map<String, Object> result = objectMapper.readValue(
                    responseBody, 
                    new TypeReference<Map<String, Object>>() {}
                );

                // Check for GraphQL errors
                if (result.containsKey("errors")) {
                    List<Map<String, Object>> errors = (List<Map<String, Object>>) result.get("errors");
                    if (!errors.isEmpty()) {
                        Map<String, Object> mainError = errors.get(0);
                        String errorName = mainError.containsKey("name") 
                            ? (String) mainError.get("name") 
                            : (String) mainError.get("message");
                        String errorMessage = (String) mainError.get("message");
                        throw new OpenCTIApiException(errorName + ": " + errorMessage);
                    }
                }

                return result;
            }
        } catch (IOException e) {
            throw new OpenCTIApiException("Failed to execute query", e);
        }
    }

    /**
     * Perform a health check against the OpenCTI API.
     *
     * @return true if the API is reachable and healthy
     */
    public boolean healthCheck() {
        try {
            log.info("Health check (platform version)...");
            String healthQuery = """
                query healthCheck {
                    about {
                        version
                    }
                }
                """;
            Map<String, Object> result = query(healthQuery);
            return result != null;
        } catch (Exception e) {
            log.error("Health check failed", e);
            return false;
        }
    }

    /**
     * Get the platform version.
     *
     * @return the platform version string
     */
    public String getPlatformVersion() {
        String versionQuery = """
            query {
                about {
                    version
                }
            }
            """;
        Map<String, Object> result = query(versionQuery);
        @SuppressWarnings("unchecked")
        Map<String, Object> data = (Map<String, Object>) result.get("data");
        @SuppressWarnings("unchecked")
        Map<String, Object> about = (Map<String, Object>) data.get("about");
        return (String) about.get("version");
    }

    /**
     * Set the applicant ID header for impersonation.
     *
     * @param applicantId the ID of the user to impersonate
     */
    public void setApplicantIdHeader(String applicantId) {
        requestHeaders.put("opencti-applicant-id", applicantId);
    }

    /**
     * Set the playbook ID header for tracking playbook execution.
     *
     * @param playbookId the ID of the playbook being executed
     */
    public void setPlaybookIdHeader(String playbookId) {
        requestHeaders.put("opencti-playbook-id", playbookId);
    }

    /**
     * Set the event ID header for event tracking.
     *
     * @param eventId the ID of the event
     */
    public void setEventId(String eventId) {
        requestHeaders.put("opencti-event-id", eventId);
    }

    /**
     * Set the draft ID header for draft mode operations.
     *
     * @param draftId the ID of the draft workspace
     */
    public void setDraftId(String draftId) {
        this.draftId = draftId;
        requestHeaders.put("opencti-draft-id", draftId);
    }

    /**
     * Set the synchronized upsert header.
     *
     * @param synchronized whether upsert should be synchronized
     */
    public void setSynchronizedUpsertHeader(boolean synchronizedValue) {
        requestHeaders.put("synchronized-upsert", synchronizedValue ? "true" : "false");
    }

    /**
     * Set the retry number header for tracking retries.
     *
     * @param retryNumber the current retry attempt number, or null to clear
     */
    public void setRetryNumber(Integer retryNumber) {
        if (retryNumber == null) {
            requestHeaders.put("opencti-retry-number", "");
        } else {
            requestHeaders.put("opencti-retry-number", String.valueOf(retryNumber));
        }
    }

    /**
     * Get a copy of current request headers.
     *
     * @param hideToken if true, masks the Authorization token with asterisks
     * @return copy of request headers
     */
    public Map<String, String> getRequestHeaders(boolean hideToken) {
        Map<String, String> headersCopy = new HashMap<>(requestHeaders);
        if (hideToken && headersCopy.containsKey("Authorization")) {
            headersCopy.put("Authorization", "*****");
        }
        return headersCopy;
    }

    /**
     * Upload a file to OpenCTI.
     *
     * @param fileName the name of the file
     * @param data the file content
     * @param mimeType the MIME type of the file
     * @return the upload result
     */
    public Map<String, Object> uploadFile(String fileName, byte[] data, String mimeType) {
        return uploadFile(fileName, data, mimeType, null);
    }

    /**
     * Upload a file to OpenCTI with optional file markings.
     *
     * @param fileName the name of the file
     * @param data the file content
     * @param mimeType the MIME type of the file
     * @param fileMarkings list of marking definition IDs to apply
     * @return the upload result
     */
    @SuppressWarnings("unchecked")
    public Map<String, Object> uploadFile(String fileName, byte[] data, String mimeType, List<String> fileMarkings) {
        if (fileName == null) {
            log.error("[upload] Missing parameter: file_name");
            return null;
        }

        log.info("Uploading a file: {}", fileName);

        String mutation = """
            mutation UploadImport($file: Upload!, $fileMarkings: [String]) {
                uploadImport(file: $file, fileMarkings: $fileMarkings) {
                    id
                    name
                }
            }
            """;

        try {
            // Build multipart request
            MultipartBody.Builder multipartBuilder = new MultipartBody.Builder()
                .setType(MultipartBody.FORM);

            // Operations
            Map<String, Object> variables = new HashMap<>();
            variables.put("file", null);
            if (fileMarkings != null) {
                variables.put("fileMarkings", fileMarkings);
            }
            Map<String, Object> operations = new HashMap<>();
            operations.put("query", mutation);
            operations.put("variables", variables);
            multipartBuilder.addFormDataPart("operations", objectMapper.writeValueAsString(operations));

            // Map
            Map<String, List<String>> map = new HashMap<>();
            map.put("0", List.of("variables.file"));
            multipartBuilder.addFormDataPart("map", objectMapper.writeValueAsString(map));

            // File
            RequestBody fileBody = RequestBody.create(data, MediaType.parse(mimeType));
            multipartBuilder.addFormDataPart("0", fileName, fileBody);

            Request request = new Request.Builder()
                .url(apiUrl)
                .headers(buildHeaders())
                .post(multipartBuilder.build())
                .build();

            try (Response response = httpClient.newCall(request).execute()) {
                String responseBody = response.body() != null ? response.body().string() : "";

                if (!response.isSuccessful()) {
                    throw new OpenCTIApiException("HTTP " + response.code() + ": " + responseBody);
                }

                return objectMapper.readValue(responseBody, new TypeReference<Map<String, Object>>() {});
            }
        } catch (IOException e) {
            throw new OpenCTIApiException("Failed to upload file", e);
        }
    }

    /**
     * Get the STIX content of any entity.
     *
     * @param id the ID of the entity
     * @return the STIX content
     */
    @SuppressWarnings("unchecked")
    public Map<String, Object> getStixContent(String id) {
        log.info("Entity in JSON: {}", id);
        String stixQuery = """
            query StixQuery($id: String!) {
                stix(id: $id)
            }
            """;
        Map<String, Object> result = query(stixQuery, Map.of("id", id));
        Map<String, Object> data = (Map<String, Object>) result.get("data");
        String stixJson = (String) data.get("stix");
        try {
            return objectMapper.readValue(stixJson, new TypeReference<Map<String, Object>>() {});
        } catch (IOException e) {
            throw new OpenCTIApiException("Failed to parse STIX content", e);
        }
    }

    /**
     * Import a STIX bundle into OpenCTI.
     *
     * @param bundle the STIX bundle as a string
     * @return the import result
     */
    @SuppressWarnings("unchecked")
    public Map<String, Object> importBundle(String bundle) {
        String importMutation = """
            mutation ImportBundle($bundle: String!) {
                stixBundlePush(bundle: $bundle)
            }
            """;
        return query(importMutation, Map.of("bundle", bundle));
    }

    /**
     * Process data returned by the OpenCTI API with multiple entities.
     *
     * @param data the data to process
     * @return processed list of entities
     */
    @SuppressWarnings("unchecked")
    public List<Map<String, Object>> processMultiple(Map<String, Object> data) {
        return processMultiple(data, false).getEntities();
    }

    /**
     * Process data returned by the OpenCTI API with multiple entities.
     *
     * @param data the data to process
     * @param withPagination whether to include pagination info
     * @return processed result with entities and optional pagination
     */
    @SuppressWarnings("unchecked")
    public PaginatedResult processMultiple(Map<String, Object> data, boolean withPagination) {
        PaginatedResult result = new PaginatedResult();

        if (data == null) {
            return result;
        }

        // Check if data has edges structure
        if (data.containsKey("edges")) {
            List<Map<String, Object>> edges = (List<Map<String, Object>>) data.get("edges");
            if (edges != null) {
                for (Map<String, Object> edge : edges) {
                    Map<String, Object> node = (Map<String, Object>) edge.get("node");
                    if (node != null) {
                        result.getEntities().add(processMultipleFields(node));
                    }
                }
            }

            // Add pagination info if present
            if (withPagination && data.containsKey("pageInfo")) {
                result.setPagination((Map<String, Object>) data.get("pageInfo"));
            }
        } else if (data instanceof List) {
            // Direct list
            for (Map<String, Object> item : (List<Map<String, Object>>) data) {
                result.getEntities().add(processMultipleFields(item));
            }
        }

        return result;
    }

    /**
     * Process data returned by the OpenCTI API with multiple fields.
     *
     * @param data the data to process
     * @return processed data with all fields
     */
    @SuppressWarnings("unchecked")
    public Map<String, Object> processMultipleFields(Map<String, Object> data) {
        if (data == null) {
            return null;
        }

        // Create a mutable copy to avoid modifying immutable maps
        Map<String, Object> result = new HashMap<>(data);

        // Process createdBy
        if (result.containsKey("createdBy") && result.get("createdBy") != null) {
            Map<String, Object> createdBy = new HashMap<>((Map<String, Object>) result.get("createdBy"));
            result.put("createdById", createdBy.get("id"));
            if (createdBy.containsKey("objectMarking")) {
                createdBy.put("objectMarking", processMultiple((Map<String, Object>) createdBy.get("objectMarking")));
                createdBy.put("objectMarkingIds", processMultipleIds((List<Map<String, Object>>) createdBy.get("objectMarking")));
            }
            result.put("createdBy", createdBy);
        } else {
            result.put("createdById", null);
        }

        // Process objectMarking
        if (result.containsKey("objectMarking")) {
            Object objectMarking = result.get("objectMarking");
            if (objectMarking instanceof Map) {
                List<Map<String, Object>> processed = processMultiple((Map<String, Object>) objectMarking);
                result.put("objectMarking", processed);
                result.put("objectMarkingIds", processMultipleIds(processed));
            } else if (objectMarking instanceof List) {
                result.put("objectMarkingIds", processMultipleIds((List<Map<String, Object>>) objectMarking));
            }
        }

        // Process objectLabel
        if (result.containsKey("objectLabel")) {
            Object objectLabel = result.get("objectLabel");
            if (objectLabel instanceof Map) {
                List<Map<String, Object>> processed = processMultiple((Map<String, Object>) objectLabel);
                result.put("objectLabel", processed);
                result.put("objectLabelIds", processMultipleIds(processed));
            } else if (objectLabel instanceof List) {
                result.put("objectLabelIds", processMultipleIds((List<Map<String, Object>>) objectLabel));
            }
        }

        // Process externalReferences
        if (result.containsKey("externalReferences")) {
            Object externalReferences = result.get("externalReferences");
            if (externalReferences instanceof Map) {
                List<Map<String, Object>> processed = processMultiple((Map<String, Object>) externalReferences);
                result.put("externalReferences", processed);
                result.put("externalReferencesIds", processMultipleIds(processed));
            }
        }

        // Process killChainPhases
        if (result.containsKey("killChainPhases")) {
            Object killChainPhases = result.get("killChainPhases");
            if (killChainPhases instanceof Map) {
                List<Map<String, Object>> processed = processMultiple((Map<String, Object>) killChainPhases);
                result.put("killChainPhases", processed);
                result.put("killChainPhasesIds", processMultipleIds(processed));
            } else if (killChainPhases instanceof List) {
                result.put("killChainPhasesIds", processMultipleIds((List<Map<String, Object>>) killChainPhases));
            }
        }

        // Process objects
        if (result.containsKey("objects")) {
            Object objects = result.get("objects");
            if (objects instanceof Map) {
                List<Map<String, Object>> processed = processMultiple((Map<String, Object>) objects);
                result.put("objects", processed);
                result.put("objectsIds", processMultipleIds(processed));
            }
        }

        // Process observables
        if (result.containsKey("observables")) {
            Object observables = result.get("observables");
            if (observables instanceof Map) {
                List<Map<String, Object>> processed = processMultiple((Map<String, Object>) observables);
                result.put("observables", processed);
                result.put("observablesIds", processMultipleIds(processed));
            }
        }

        return result;
    }

    /**
     * Process data returned by the OpenCTI API and extract IDs.
     *
     * @param data the list of data to extract IDs from
     * @return list of IDs
     */
    public List<String> processMultipleIds(List<Map<String, Object>> data) {
        List<String> result = new ArrayList<>();
        if (data != null) {
            for (Map<String, Object> item : data) {
                if (item != null && item.containsKey("id")) {
                    result.add((String) item.get("id"));
                }
            }
        }
        return result;
    }

    /**
     * Check if a value is not empty.
     *
     * @param value the value to check
     * @return true if the value is not empty
     */
    public boolean notEmpty(Object value) {
        if (value == null) {
            return false;
        }
        if (value instanceof String) {
            return !((String) value).isEmpty();
        }
        if (value instanceof Collection) {
            Collection<?> collection = (Collection<?>) value;
            return !collection.isEmpty() && collection.stream().anyMatch(item -> {
                if (item instanceof String) {
                    return !((String) item).isEmpty();
                }
                return item != null;
            });
        }
        if (value instanceof Map) {
            return !((Map<?, ?>) value).isEmpty();
        }
        if (value instanceof Boolean || value instanceof Number) {
            return true;
        }
        return true;
    }

    private Headers buildHeaders() {
        Headers.Builder builder = new Headers.Builder();
        for (Map.Entry<String, String> header : requestHeaders.entrySet()) {
            builder.add(header.getKey(), header.getValue());
        }
        if (StringUtils.isNotBlank(draftId)) {
            builder.add("opencti-draft-id", draftId);
        }
        return builder.build();
    }

    /**
     * Builder for OpenCTIApiClient.
     */
    public static class Builder {
        private String url;
        private String token;
        private boolean sslVerify = false;
        private java.net.Proxy proxy;
        private boolean bundleSendToQueue = true;
        private String customHeaders;
        private boolean performHealthCheck = true;
        private int requestTimeout = 300;
        private String provider;

        /**
         * Set the OpenCTI platform URL.
         *
         * @param url the platform URL (e.g., "http://localhost:4000")
         * @return this builder
         */
        public Builder url(String url) {
            this.url = url;
            return this;
        }

        /**
         * Set the API authentication token.
         *
         * @param token the API token
         * @return this builder
         */
        public Builder token(String token) {
            this.token = token;
            return this;
        }

        /**
         * Set whether to verify SSL certificates.
         *
         * @param sslVerify true to verify SSL certificates
         * @return this builder
         */
        public Builder sslVerify(boolean sslVerify) {
            this.sslVerify = sslVerify;
            return this;
        }

        /**
         * Set the proxy to use for connections.
         *
         * @param proxy the proxy configuration
         * @return this builder
         */
        public Builder proxy(java.net.Proxy proxy) {
            this.proxy = proxy;
            return this;
        }

        /**
         * Set whether bundles should be sent to queue.
         *
         * @param bundleSendToQueue true to send bundles to queue
         * @return this builder
         */
        public Builder bundleSendToQueue(boolean bundleSendToQueue) {
            this.bundleSendToQueue = bundleSendToQueue;
            return this;
        }

        /**
         * Set custom headers in format "header01:value;header02:value".
         *
         * @param customHeaders the custom headers string
         * @return this builder
         */
        public Builder customHeaders(String customHeaders) {
            this.customHeaders = customHeaders;
            return this;
        }

        /**
         * Set whether to perform a health check on initialization.
         *
         * @param performHealthCheck true to perform health check
         * @return this builder
         */
        public Builder performHealthCheck(boolean performHealthCheck) {
            this.performHealthCheck = performHealthCheck;
            return this;
        }

        /**
         * Set the request timeout in seconds.
         *
         * @param requestTimeout timeout in seconds
         * @return this builder
         */
        public Builder requestTimeout(int requestTimeout) {
            this.requestTimeout = requestTimeout;
            return this;
        }

        /**
         * Set the provider string for User-Agent header.
         *
         * @param provider provider in format "name/version" (e.g., "myapp/1.0.0")
         * @return this builder
         */
        public Builder provider(String provider) {
            this.provider = provider;
            return this;
        }

        /**
         * Build the OpenCTIApiClient instance.
         *
         * @return a new OpenCTIApiClient
         */
        public OpenCTIApiClient build() {
            return new OpenCTIApiClient(this);
        }
    }
}

