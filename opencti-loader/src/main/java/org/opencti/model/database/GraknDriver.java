package org.opencti.model.database;

import ai.grakn.GraknTxType;
import ai.grakn.Keyspace;
import ai.grakn.client.Grakn;
import ai.grakn.util.SimpleURI;
import org.cfg4j.provider.ConfigurationProvider;
import org.neo4j.driver.v1.AuthTokens;
import org.neo4j.driver.v1.Driver;
import org.neo4j.driver.v1.GraphDatabase;
import org.neo4j.driver.v1.Session;

import java.util.List;

import static org.neo4j.driver.v1.Values.parameters;

public class GraknDriver extends LoaderDriver {

    private Grakn.Session session;

    public GraknDriver(ConfigurationProvider cp) {
        super(cp);
    }

    @Override
    public void init(ConfigurationProvider cp) {
        String uri = cp.getProperty("grakn.uri", String.class);
        String space = cp.getProperty("grakn.keyspace", String.class);
        Grakn grakn = new Grakn(new SimpleURI(uri));
        Keyspace keyspace = Keyspace.of(space);
        session = grakn.session(keyspace);
    }

    @Override
    @SuppressWarnings("ResultOfMethodCallIgnored")
    public Object execute(BaseQuery q) {
        try (Grakn.Transaction transaction = session.transaction(GraknTxType.WRITE)) {
            List<?> results = transaction.graql().parse(q.getQuery()).execute();
            transaction.commit();
            return results.size() > 0 ? results.get(0) : null;
        }
    }

    @Override
    public void close() {
        //Nothing to do
    }
}
