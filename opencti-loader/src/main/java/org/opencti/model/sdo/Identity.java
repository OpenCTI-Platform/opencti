package org.opencti.model.sdo;

import org.opencti.model.StixBase;
import org.opencti.model.database.LoaderDriver;

import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;

import static java.lang.String.format;
import static org.opencti.model.database.BaseQuery.from;
import static org.opencti.model.utils.StixUtils.prepare;

public class Identity extends Domain {

    @Override
    public boolean isImplemented() {
        return true;
    }

    @Override
    public void neo4j(LoaderDriver driver, Map<String, StixBase> stixElements) {
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

    @Override
    public void grakn(LoaderDriver driver, Map<String, StixBase> stixElements) {
        AtomicInteger nbRequests = new AtomicInteger();
        Object identity = driver.execute(from(format("match $m isa Identity has stix_id %s; get;", prepare(getId()))));
        nbRequests.getAndIncrement();
        if (identity == null) {
            String identityCreation = format("insert $m isa Identity " +
                            "has stix_id %s " +
                            "has name %s " +
                            "has identity_class %s " +
                            "has type %s " +
                            "has modified %s " +
                            "has created %s;",
                    prepare(getId()),
                    prepare(getName()),
                    prepare(getIdentity_class()),
                    prepare(getType()),
                    getModified(),
                    getCreated()
            );
            driver.execute(from(identityCreation));
            nbRequests.getAndIncrement();
        }
    }

    private String name;
    private String identity_class;

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    private String getIdentity_class() {
        return identity_class;
    }

    public void setIdentity_class(String identity_class) {
        this.identity_class = identity_class;
    }
}
