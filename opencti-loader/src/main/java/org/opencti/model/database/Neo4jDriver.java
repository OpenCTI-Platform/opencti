package org.opencti.model.database;

import org.cfg4j.provider.ConfigurationProvider;
import org.neo4j.driver.v1.*;

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
    public Object execute(BaseQuery q) {
        try (Session session = driver.session()) {
            StatementResult statementResult = session.writeTransaction(tx -> tx.run(q.getQuery(), parameters(q.getParameters())));
            return statementResult.single().asMap();
        }
    }

    @Override
    public void close() {
        driver.close();
    }
}
