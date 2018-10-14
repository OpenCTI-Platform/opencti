package org.luatix.base;

import org.cfg4j.provider.ConfigurationProvider;
import org.neo4j.ogm.config.Configuration;
import org.neo4j.ogm.session.Session;
import org.neo4j.ogm.session.SessionFactory;

public class Database {

    private SessionFactory sessionFactory;

    public Database(ConfigurationProvider cp) {
        String uri = cp.getProperty("neo4j.uri", String.class);
        String username = cp.getProperty("neo4j.username", String.class);
        String password = cp.getProperty("neo4j.password", String.class);
        Configuration configuration = new Configuration.Builder()
                .uri(uri)
                .credentials(username, password)
                .build();
        sessionFactory = new SessionFactory(configuration, "org.luatix.domain");
    }

    public Session session() {
        return sessionFactory.openSession();
    }
}
