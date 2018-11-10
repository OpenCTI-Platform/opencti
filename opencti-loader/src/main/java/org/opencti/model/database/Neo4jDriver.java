package org.opencti.model.database;

import org.cfg4j.provider.ConfigurationProvider;
import org.neo4j.driver.v1.AuthTokens;
import org.neo4j.driver.v1.Driver;
import org.neo4j.driver.v1.GraphDatabase;
import org.neo4j.driver.v1.Session;

import java.util.List;

import static org.neo4j.driver.v1.Values.parameters;

public class Neo4jDriver extends LoaderDriver {

    private Driver driver;

    public Neo4jDriver(ConfigurationProvider cp) {
        super(cp);
    }

    @Override
    public void init(ConfigurationProvider cp) {
        String uri = cp.getProperty("neo4j.uri", String.class);
        String username = cp.getProperty("neo4j.username", String.class);
        String password = cp.getProperty("neo4j.password", String.class);
        driver = GraphDatabase.driver(uri, AuthTokens.basic(username, password));
    }

    @Override
    @SuppressWarnings("ResultOfMethodCallIgnored")
    public void execute(BaseQuery q) {
        try (Session session = driver.session()) {
            session.writeTransaction(tx -> tx.run(q.getQuery(), parameters(q.getParameters())));
        }
    }

    @Override
    public void close() {
        driver.close();
    }
}
