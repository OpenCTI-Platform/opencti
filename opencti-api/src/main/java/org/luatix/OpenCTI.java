package org.luatix;

import com.coxautodev.graphql.tools.SchemaParser;
import graphql.ExecutionInput;
import graphql.GraphQL;
import graphql.execution.instrumentation.tracing.TracingInstrumentation;
import graphql.schema.GraphQLSchema;
import org.cfg4j.provider.ConfigurationProvider;
import org.cfg4j.provider.ConfigurationProviderBuilder;
import org.cfg4j.source.ConfigurationSource;
import org.cfg4j.source.context.filesprovider.ConfigFilesProvider;
import org.cfg4j.source.files.FilesConfigurationSource;
import org.cfg4j.source.reload.ReloadStrategy;
import org.cfg4j.source.reload.strategy.PeriodicalReloadStrategy;
import org.eclipse.jetty.server.Connector;
import org.eclipse.jetty.server.Server;
import org.eclipse.jetty.server.ServerConnector;
import org.eclipse.jetty.servlet.ServletHandler;
import org.luatix.base.Database;
import org.luatix.api.generic.About;
import org.luatix.servlet.AuthenticationServlet;
import org.luatix.servlet.GraphQLSecurityFilter;
import org.luatix.servlet.GraphQLEndpoint;
import org.luatix.api.user.UserQuery;

import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.concurrent.TimeUnit;

import static java.util.Arrays.asList;

public class OpenCTI {

    /**
     * @return GraphQLSchema
     */
    public static GraphQLSchema buildSchema() {
        AppContext context = AppContext.context();
        context.config(configurationProvider());
        context.database(new Database());

        SchemaParser schemaParser = SchemaParser.newParser()
                .file("opencti.graphqls")
                .resolvers(new About(), new UserQuery())
                .build();
        return schemaParser.makeExecutableSchema();
    }

    @SuppressWarnings("ArraysAsListWithZeroOrOneArgument")
    private static ConfigurationProvider configurationProvider() {
        Path applicationConfig = Paths.get("config/application.properties").toAbsolutePath();
        ConfigFilesProvider configFilesProvider = () -> asList(applicationConfig);
        ConfigurationSource source = new FilesConfigurationSource(configFilesProvider);
        ReloadStrategy reloadStrategy = new PeriodicalReloadStrategy(5, TimeUnit.SECONDS);
        return new ConfigurationProviderBuilder()
                .withConfigurationSource(source)
                .withReloadStrategy(reloadStrategy)
                .build();
    }

    public static void main(String[] args) throws Exception {
        //Build the schema for validation only
        buildSchema();
        //Create http server
        Server server = new Server();
        //Listen to a specific port
        ServerConnector connector = new ServerConnector(server);
        connector.setPort(8080);
        server.setConnectors(new Connector[]{connector});
        //Register the graphQL servlet
        ServletHandler servletHandler = new ServletHandler();
        server.setHandler(servletHandler);
        //Security of /graphQL endpoint through servlet filter.
        servletHandler.addFilterWithMapping(GraphQLSecurityFilter.class, "/graphql", 0);
        //Register the graphQL endpoint
        servletHandler.addServletWithMapping(AuthenticationServlet.class, "/auth");
        servletHandler.addServletWithMapping(GraphQLEndpoint.class, "/graphql");
        //Start the server
        server.start();
        server.dump(System.err);
        server.join();
    }
}
