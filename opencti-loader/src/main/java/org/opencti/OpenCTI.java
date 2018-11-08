package org.opencti;

import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.cfg4j.provider.ConfigurationProvider;
import org.cfg4j.provider.ConfigurationProviderBuilder;
import org.cfg4j.source.ConfigurationSource;
import org.cfg4j.source.context.filesprovider.ConfigFilesProvider;
import org.cfg4j.source.files.FilesConfigurationSource;
import org.neo4j.driver.v1.AuthTokens;
import org.neo4j.driver.v1.Driver;
import org.neo4j.driver.v1.GraphDatabase;
import org.opencti.model.StixBase;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;

import static java.util.Arrays.asList;

public class OpenCTI {

    public static Driver driver;
    private static List<StixBase> filesToProcess = new ArrayList<>();
    private static ConfigurationProvider cp;
    private static final ObjectMapper MAPPER = new ObjectMapper();

    static {
        cp = configurationProvider();
        driver = database();
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

    private static Driver database() {
        String uri = cp.getProperty("neo4j.uri", String.class);
        String username = cp.getProperty("neo4j.username", String.class);
        String password = cp.getProperty("neo4j.password", String.class);
        return GraphDatabase.driver(uri, AuthTokens.basic(username, password));
    }

    @SuppressWarnings("unchecked")
    private static void stixFileHandler(Path pathSelected) {
        try {
            StixBase stixElement = MAPPER.readValue(pathSelected.toFile(), StixBase.class);
            filesToProcess.add(stixElement);
        } catch (Exception e) {
            //System.out.println("Type of file not implemented yet (" + pathSelected + ")");
        }
    }

    private static void filesToProcess() throws IOException {
        String path = cp.getProperty("stix2.files.path", String.class);
        long startFileCatch = System.currentTimeMillis();
        Files.walk(Paths.get(path)).parallel()
                .filter(pathFilter -> pathFilter.toString().endsWith(".json"))
                .forEach(OpenCTI::stixFileHandler);
        long endFileCatch = System.currentTimeMillis();
        System.out.println("Files walk completed in " + (endFileCatch - startFileCatch) + " millis");
        System.out.println(filesToProcess.size() + " files to process");
        long startNeoProcess = System.currentTimeMillis();
        AtomicInteger index = new AtomicInteger();
        filesToProcess.parallelStream().forEach(file -> {
            index.getAndIncrement();
            file.load();
            System.out.print("\rProcessing " + filesToProcess.size() + "/" + index.get());
        });
        long endNeoProcess = System.currentTimeMillis();
        System.out.println("\r\nNeo4j integration completed in " + ((endNeoProcess - startNeoProcess) / 1000) + " seconds");
        driver.close();
    }

    public static void main(String[] args) throws IOException {
        filesToProcess();
    }
}
