package org.luatix;

import com.coxautodev.graphql.tools.SchemaParser;
import graphql.schema.GraphQLSchema;
import org.eclipse.jetty.server.Connector;
import org.eclipse.jetty.server.Server;
import org.eclipse.jetty.server.ServerConnector;
import org.eclipse.jetty.servlet.ServletHandler;
import org.luatix.Basic.About;
import org.luatix.Servlet.GraphQLEndpoint;
import org.luatix.User.UserQuery;


public class OpenCTI {

    /**
     * @return GraphQLSchema
     */
    public static GraphQLSchema buildSchema() {
        SchemaParser schemaParser = SchemaParser.newParser()
                .file("opencti.graphqls")
                .resolvers(new About(), new UserQuery())
                .build();
        return schemaParser.makeExecutableSchema();
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
        servletHandler.addServletWithMapping(GraphQLEndpoint.class, "/graphql");
        //Start the server
        server.start();
        server.dump(System.err);
        server.join();
    }
}
