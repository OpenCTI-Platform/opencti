package org.opencti;

import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.cfg4j.provider.ConfigurationProvider;
import org.cfg4j.provider.ConfigurationProviderBuilder;
import org.cfg4j.source.ConfigurationSource;
import org.cfg4j.source.context.filesprovider.ConfigFilesProvider;
import org.cfg4j.source.files.FilesConfigurationSource;
import org.opencti.model.StixBase;
import org.opencti.model.StixElement;
import org.opencti.model.database.*;
import org.opencti.model.sdo.Domain;
import org.opencti.model.sro.Relationship;
import org.opencti.model.utils.StixUtils;

import java.lang.reflect.Method;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Function;
import java.util.stream.Collectors;

import static java.util.Arrays.asList;

public class OpenCTI {

    private static ConfigurationProvider cp;
    private static Map<String, StixElement> stixElements = new HashMap<>();
    private static final ObjectMapper MAPPER = new ObjectMapper();

    static {
        cp = configurationProvider();
        MAPPER.configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);
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
            StixBase stixElement = MAPPER.readValue(pathSelected.toFile(), StixBase.class);
            Map<String, StixElement> stixBaseMap = stixElement.toStixElements().stream()
                    .filter(StixElement::isImplemented)
                    .collect(Collectors.toMap(StixElement::getId, Function.identity()));
            stixElements.putAll(stixBaseMap);
        } catch (Exception e) {
            //System.out.println("Type of file not implemented yet (" + pathSelected + ")");
        }
    }

    private static void filesToProcess() throws Exception {
        String databaseType = cp.getProperty("database.type", String.class);
        Class<?> driverClass = Class.forName(String.format("org.opencti.model.database.%sDriver", databaseType));
        LoaderDriver driver = (LoaderDriver) driverClass.getConstructor(ConfigurationProvider.class).newInstance(cp);
        String path = cp.getProperty("stix2.files.path", String.class);
        long startFileCatch = System.currentTimeMillis();
        //Load all JSON
        Files.walk(Paths.get(path)).parallel()
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
                    try {
                        Method method = file.getClass().getMethod(databaseType.toLowerCase(), LoaderDriver.class, Map.class);
                        //method.invoke(file, driver, stixElements);
                        System.out.format("\rProcessing domain %d/%d", domainsCount, domainIndex.get());
                    } catch (Exception e) {
                        throw new RuntimeException(e.getCause());
                    }
                });
        long endNeoProcess = System.currentTimeMillis();
        long domainProcessingTime = endNeoProcess - startNeoProcess;
        System.out.println("\r\nStix domain integration completed " +
                "in " + (domainProcessingTime / 1000) + " seconds " +
                "(Query average: " + (domainProcessingTime / (2 * domainsCount)) + " ms)");

        //Process extra relations
        List<GraknRelation> graknRelations = stixElements.values().stream()
                .map(e -> e.extraRelations(stixElements))
                .flatMap(List::stream)
                .collect(Collectors.toList());

        System.out.println("Processing #" + graknRelations.size() + " Stix extra relations");
        long startExtraRelationProcess = System.currentTimeMillis();
        AtomicInteger extraRelationIndex = new AtomicInteger();
        graknRelations.parallelStream().forEach(relation -> {
            extraRelationIndex.getAndIncrement();
            StixUtils.createGraknRelation(driver, relation);
            System.out.format("\rProcessing extra relation %d/%d", graknRelations.size(), extraRelationIndex.get());
        });
        long endExtraRelationProcess = System.currentTimeMillis();
        long relationProcessingTime = endExtraRelationProcess - startExtraRelationProcess;
        System.out.println("\r\nStix extra relation integration completed " +
                "in " + (relationProcessingTime / 1000) + " seconds " +
                "(Query average: " + (relationProcessingTime / (2 * graknRelations.size())) + " ms)");

        //Close driver
        driver.close();
    }

    public static void main(String[] args) throws Exception {
        filesToProcess();
    }
}
