package org.opencti.model.database;

import ai.grakn.GraknTxType;
import ai.grakn.Keyspace;
import ai.grakn.client.Grakn;
import ai.grakn.graql.GetQuery;
import ai.grakn.graql.Query;
import ai.grakn.graql.QueryBuilder;
import ai.grakn.util.SimpleURI;
import javafx.util.Pair;
import org.apache.commons.io.IOUtils;
import org.cfg4j.provider.ConfigurationProvider;
import org.opencti.model.base.Stix;
import org.opencti.model.sro.RolePair;
import org.opencti.schema.Entity;
import org.opencti.schema.Schema;

import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class GraknDriver {

    private Grakn.Session session;
    private Map<String, RolePair> roles = new HashMap<>();

    public GraknDriver(ConfigurationProvider cp) throws Exception {
        mapFromStixSpecification();
        String uri = cp.getProperty("grakn.uri", String.class);
        String space = cp.getProperty("grakn.keyspace", String.class);
        Grakn grakn = new Grakn(new SimpleURI(uri));
        Keyspace keyspace = Keyspace.of(space);
        session = grakn.session(keyspace);
    }

    private void mapFromStixSpecification() {
        //Attack-Pattern
        roles.put("Attack-Pattern|Identity>targets", new RolePair("source", "target"));
        roles.put("Attack-Pattern|Vulnerability>targets", new RolePair("source", "target"));
        roles.put("Attack-Pattern|Malware>uses", new RolePair("user", "usage"));
        roles.put("Attack-Pattern|Tool>uses", new RolePair("user", "usage"));

        //Campaign
        //TODO

        //Course-Of-Action
        roles.put("Course-Of-Action|Attack-Pattern>mitigates", new RolePair("mitigation", "problem"));
        roles.put("Course-Of-Action|Malware>mitigates", new RolePair("mitigation", "problem"));
        roles.put("Course-Of-Action|Tool>mitigates", new RolePair("mitigation", "problem"));
        roles.put("Course-Of-Action|Vulnerability>mitigates", new RolePair("mitigation", "problem"));

        //Identity
        //Nothing

        //Indicator
        //TODO

        //Intrusion-Set
        roles.put("Intrusion-Set|Threat-Actor>threat-actor", new RolePair("origin", "attribution")); //TODO ASK Sam
        roles.put("Intrusion-Set|Identity>targets", new RolePair("source", "target"));
        roles.put("Intrusion-Set|Vulnerability>targets", new RolePair("source", "target"));
        roles.put("Intrusion-Set|Malware>uses", new RolePair("user", "usage"));
        roles.put("Intrusion-Set|Tool>uses", new RolePair("user", "usage"));
        roles.put("Intrusion-Set|Attack-Pattern>uses", new RolePair("user", "usage"));

        //Malware
        roles.put("Malware|Identity>targets", new RolePair("source", "target"));
        roles.put("Malware|Vulnerability>targets", new RolePair("source", "target"));
        roles.put("Malware|Tool>uses", new RolePair("user", "usage"));
        roles.put("Malware|Attack-Pattern>uses", new RolePair("user", "usage")); //NOT IN SPECIFICATION
        roles.put("Malware|Malware>variant-of", new RolePair("original", "variation"));

        //Report
        //TODO

        //Threat-Actor
        //TODO

        //Tool
        roles.put("Tool|Identity>targets", new RolePair("source", "target"));
        roles.put("Tool|Vulnerability>targets", new RolePair("source", "target"));
        roles.put("Tool|Attack-Pattern>uses", new RolePair("user", "usage")); //NOT IN SPECIFICATION

        //Vulnerability
        //TODO
    }

    public void write(String query) {
        try (Grakn.Transaction transaction = session.transaction(GraknTxType.WRITE)) {
            List<?> results = transaction.graql().parse(query).execute();
            transaction.commit();
            Object data = results.size() > 0 ? results.get(0) : null;
            if(data == null) {
                throw new RuntimeException("Error will writing data to grakn, " + query);
            }
        }
    }

    public Object read(String query) {
        try (Grakn.Transaction transaction = session.transaction(GraknTxType.READ)) {
            List<?> results = transaction.graql().parse(query).execute();
            transaction.commit();
            return results.size() > 0 ? results.get(0) : null;
        }
    }

    public RolePair resolveRelationRoles(String relationName, String from, String to) {
        String key = from + "|" + to + ">" + relationName;
        RolePair resolved = roles.get(key);
        if(resolved == null) {
            throw new RuntimeException(key + " not yet implemented");
        }
        return resolved;
    }

    private String getSchemaContent() throws Exception {
        Path schemaPath = Paths.get("schema/stix2.gql").toAbsolutePath();
        return IOUtils.toString(new FileReader(schemaPath.toFile()));
    }

    public void loadSchema() throws Exception {
        String content = getSchemaContent();
        write(content);
    }
}
