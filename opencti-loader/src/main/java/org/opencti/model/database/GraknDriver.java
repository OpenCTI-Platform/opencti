package org.opencti.model.database;

import ai.grakn.GraknTxType;
import ai.grakn.Keyspace;
import ai.grakn.client.Grakn;
import ai.grakn.util.SimpleURI;
import org.apache.commons.io.IOUtils;
import org.cfg4j.provider.ConfigurationProvider;
import org.opencti.mapping.RelationMapping;
import org.opencti.mapping.StixMapper;

import java.io.FileReader;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.List;
import java.util.Map;

import static org.opencti.OpenCTI.JSON_MAPPER;

public class GraknDriver {

    private Grakn.Session session;
    private Map<String, RelationMapping> roles;

    public GraknDriver(ConfigurationProvider cp) throws Exception {
        mapFromStixSpecification();
        String uri = cp.getProperty("grakn.uri", String.class);
        String space = cp.getProperty("grakn.keyspace", String.class);
        Grakn grakn = new Grakn(new SimpleURI(uri));
        Keyspace keyspace = Keyspace.of(space);
        session = grakn.session(keyspace);
    }

    private void mapFromStixSpecification() throws Exception {
        Path mappingConfig = Paths.get("config/roles_mappings.json").toAbsolutePath();
        StixMapper stixMapper = JSON_MAPPER.readValue(mappingConfig.toFile(), StixMapper.class);
        roles = stixMapper.mappings();
    }

    public void write(String query) {
        try (Grakn.Transaction transaction = session.transaction(GraknTxType.WRITE)) {
            List<?> results = transaction.graql().parse(query).execute();
            transaction.commit();
            Object data = results.size() > 0 ? results.get(0) : null;
            if (data == null) {
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

    public RelationMapping resolveRelationRoles(String relationName, String from, String to) {
        String key = from + "|" + to + ">" + relationName;
        RelationMapping resolved = roles.get(key);
        if (resolved == null) {
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
