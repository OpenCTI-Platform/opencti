package org.opencti.model.sdo;

import org.opencti.model.database.LoaderDriver;

import static org.opencti.model.database.BaseQuery.from;

public class Identity extends Domain {
    @Override
    public void neo4j(LoaderDriver driver) {
        String query = "MERGE (identity:Identity {id: $id}) " +
                "ON CREATE SET identity = {" +
                /**/"id: $id, " +
                /**/"created: $created, " +
                /**/"modified: $modified, " +
                /**/"identity_class: $identity_class " +
                "} " +
                "ON MATCH SET identity.name = $name, " +
                /**/"identity.created = $created, " +
                /**/"identity.modified = $modified, " +
                /**/"identity.identity_class = $identity_class";
        driver.execute(from(query).withParams("id", getId(),
                "created", getCreated(),
                "modified", getModified(),
                "identity_class", getIdentity_class()
        ));
    }

    private String identity_class;

    private String getIdentity_class() {
        return identity_class;
    }

    public void setIdentity_class(String identity_class) {
        this.identity_class = identity_class;
    }
}
