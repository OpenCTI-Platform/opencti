package org.opencti.model.sdo;

import org.opencti.model.database.BaseQuery;

import java.util.List;

import static java.util.Collections.singletonList;
import static org.opencti.model.database.BaseQuery.from;

public class Identity extends Domain {
    @Override
    public List<BaseQuery> neo4j() {
        String query = "MERGE (identity:Identity {id: $id}) " +
                "ON CREATE SET identity = {" +
                /**/"id: $id, " +
                /**/"name: $name, " +
                /**/"description: $description, " +
                /**/"created: $created, " +
                /**/"modified: $modified, " +
                /**/"identity_class: $identity_class " +
                "} " +
                "ON MATCH SET identity.name = $name, " +
                /**/"identity.description = $description, " +
                /**/"identity.created = $created, " +
                /**/"identity.modified = $modified, " +
                /**/"identity.identity_class = $identity_class";
        return singletonList(from(query).withParams("id", getId(),
                "name", getName(),
                "description", getDescription(),
                "created", getCreated(),
                "modified", getModified(),
                "identity_class", getIdentity_class()
        ));
    }

    private String identity_class;

    public String getIdentity_class() {
        return identity_class;
    }

    public void setIdentity_class(String identity_class) {
        this.identity_class = identity_class;
    }
}
