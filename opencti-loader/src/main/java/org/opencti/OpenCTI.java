package org.opencti;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.exc.InvalidTypeIdException;
import org.cfg4j.provider.ConfigurationProvider;
import org.cfg4j.provider.ConfigurationProviderBuilder;
import org.cfg4j.source.ConfigurationSource;
import org.cfg4j.source.context.filesprovider.ConfigFilesProvider;
import org.cfg4j.source.files.FilesConfigurationSource;
import org.opencti.model.base.Stix;
import org.opencti.model.base.StixBase;
import org.opencti.model.database.GraknDriver;
import org.opencti.model.sro.Relationship;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Function;
import java.util.stream.Collectors;

import static java.util.Arrays.asList;

public class OpenCTI {

    private static ConfigurationProvider cp;
    private static Map<String, Stix> stixElements = new HashMap<>();
    public static final ObjectMapper JSON_MAPPER = new ObjectMapper();

    static {
        cp = configurationProvider();
        JSON_MAPPER.configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);
        JSON_MAPPER.configure(JsonParser.Feature.ALLOW_COMMENTS, true);
        //Setup the max number of concurrent integration
        System.setProperty("java.util.concurrent.ForkJoinPool.common.parallelism",
                cp.getProperty("thread.number", String.class));
    }

    @SuppressWarnings("ArraysAsListWithZeroOrOneArgument")
    private static ConfigurationProvider configurationProvider() {
        Path applicationConfig = Paths.get("config/application.properties").toAbsolutePath();
        ConfigFilesProvider configFilesProvider = () -> asList(applicationConfig);
        ConfigurationSource source = new FilesConfigurationSource(configFilesProvider);
        return new ConfigurationProviderBuilder()
                .withConfigurationSource(source)
                .build();
    }

    @SuppressWarnings("unchecked")
    private static void stixFileHandler(Path pathSelected) {
        try {
            StixBase stixElement = JSON_MAPPER.readValue(pathSelected.toFile(), StixBase.class);
            Map<String, Stix> stixBaseMap = stixElement.toStixElements().stream()
                    .filter(Stix::isImplemented)
                    .collect(Collectors.toMap(Stix::getId, Function.identity(), (stix1, stix2) -> stix1));
            stixElements.putAll(stixBaseMap);
        } catch (InvalidTypeIdException e) {
            //System.out.println("Ignoring " + pathSelected);
        } catch (Exception e) {
            throw new RuntimeException("Error processing (" + pathSelected + ")", e);
        }
    }

    private static void filesToProcess(GraknDriver driver) throws Exception {
        String path = cp.getProperty("stix2.files.path", String.class);
        long startFileCatch = System.currentTimeMillis();
        //Load all JSON
        Files.walk(Paths.get(path))
                .filter(pathFilter -> pathFilter.toString().endsWith(".json"))
                .forEach(OpenCTI::stixFileHandler);

        long endFileCatch = System.currentTimeMillis();
        System.out.println("Files walk completed in " + (endFileCatch - startFileCatch) + " millis");
        long startNeoProcess = System.currentTimeMillis();
        AtomicInteger domainIndex = new AtomicInteger();
        //Create all the domains.
        long domainsCount = stixElements.values().stream().filter(s -> !(s instanceof Relationship)).count();

        System.out.println("Processing #" + domainsCount + " Stix domain objects");
        stixElements.values()
                .parallelStream()
                .filter(s -> !(s instanceof Relationship))
                .forEach(file -> {
                    domainIndex.getAndIncrement();
                    file.load(driver, stixElements);
                    System.out.format("\rProcessing domain %d/%d", domainsCount, domainIndex.get());
                });

        long endNeoProcess = System.currentTimeMillis();
        long domainProcessingTime = endNeoProcess - startNeoProcess;
        System.out.println("\r\nStix domain integration completed " +
                "in " + (domainProcessingTime / 1000) + " seconds " +
                "(Query average: " + (domainProcessingTime / (2 * domainsCount)) + " ms)");

        //Add all stix relations
        List<List<Relationship>> relationsToProcess = new LinkedList<>();
        List<Relationship> extraRelations = stixElements.values()
                .parallelStream()
                .filter(s -> s instanceof Relationship)
                .map(Relationship.class::cast)
                .collect(Collectors.toList());
        List<Relationship> stixRelations = stixElements.values().stream()
                .map(e -> e.extraRelations(stixElements))
                .flatMap(List::stream)
                .collect(Collectors.toList());
        relationsToProcess.add(extraRelations);
        relationsToProcess.add(stixRelations);

        int nbRelationsToProcess = extraRelations.size() + stixRelations.size();
        System.out.println("Processing #" + nbRelationsToProcess + " Stix extra relations");
        long startExtraRelationProcess = System.currentTimeMillis();
        AtomicInteger extraRelationIndex = new AtomicInteger();
        relationsToProcess.forEach(list -> {
            list.parallelStream().forEach(relation -> {
                extraRelationIndex.getAndIncrement();
                relation.load(driver, stixElements);
                System.out.format("\rProcessing extra relation %d/%d", nbRelationsToProcess, extraRelationIndex.get());
            });
        });

        long endExtraRelationProcess = System.currentTimeMillis();
        long relationProcessingTime = endExtraRelationProcess - startExtraRelationProcess;
        System.out.println("\r\nStix extra relation integration completed " +
                "in " + (relationProcessingTime / 60000) + " minutes " +
                "(Query average: " + (relationProcessingTime / (2 * nbRelationsToProcess)) + " ms)");
    }

    private static void loadStixSchema(GraknDriver driver) throws Exception {
        System.out.println("Loading stix2 schema to grakn");
        long startLoadSchema = System.currentTimeMillis();
        driver.loadSchema();
        long endLoadSchema = System.currentTimeMillis();
        System.out.println("Stix2 schema loaded in " + (endLoadSchema - startLoadSchema) / 1000 + " seconds");
    }

    public static void main(String[] args) throws Exception {
        GraknDriver driver = new GraknDriver(cp);
        loadStixSchema(driver);
        filesToProcess(driver);
    }
}
