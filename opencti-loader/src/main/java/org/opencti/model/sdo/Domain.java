package org.opencti.model.sdo;

import org.opencti.model.StixBase;
import org.opencti.model.database.LoaderDriver;

import java.util.List;

import static java.lang.String.format;
import static org.opencti.model.database.BaseQuery.from;

public abstract class Domain extends StixBase {

    @Override
    public void neo4j(LoaderDriver driver) {
        String type = this.getClass().getSimpleName();
        String name = type.toLowerCase();
        //Create a new domain
        String query = "MERGE (" + name + ":" + type + " { id: $id }) " +
                "ON CREATE SET " + name + " = {" +
                /**/"id: $id, " +
                /**/"name: $name, " +
                /**/"description: $description, " +
                /**/"created: $created, " +
                /**/"modified: $modified " +
                "} " +
                "ON MATCH SET " +
                /**/name + ".name = $name, " +
                /**/name + ".description = $description, " +
                /**/name + ".created = $created, " +
                /**/name + ".modified = $modified";
        driver.execute(from(query).withParams("id", getId(),
                "name", getName(),
                "description", getDescription(),
                "created", getCreated(),
                "modified", getModified()));

        //Create the created_ref
        if (getCreated_by_ref() != null) {
            String identityQuery = "MERGE (identity:Identity {id: $identityId}) ON CREATE SET identity={id: $identityId}";
            driver.execute(from(identityQuery).withParams("identityId", getCreated_by_ref()));
            String relationQuery = "MATCH (" + name + ":" + type + " {id: $nameId}), (identity:Identity {id: $identityId}) " +
                    "MERGE (" + name + ")-[:created_by]->(identity)";
            driver.execute(from(relationQuery).withParams("nameId", getId(), "identityId", getCreated_by_ref()));
        }

        //Marking refs
        if (object_marking_refs != null) {
            getObject_marking_refs().forEach(marking -> {
                //Create entity
                String markingQuery = "MERGE (marking:MarkingDefinition {id: $markingId}) ON CREATE SET marking={id: $markingId}";
                driver.execute(from(markingQuery).withParams("markingId", marking));
                //Create relation
                String markingRelationQuery = "MATCH (" + name + ":" + type + " {id: $nameId}), (marking:MarkingDefinition {id: $markingId}) " +
                        "MERGE (" + name + ")-[:object_marking]->(marking)";
                driver.execute(from(markingRelationQuery).withParams("nameId", getId(), "markingId", marking));
            });
        }
    }

    @Override
    public void grakn(LoaderDriver driver) {
        String type = this.getClass().getSimpleName().toLowerCase();
        //match $p has identifier "Mary Guthrie"; insert $p has middlename "Mathilda"; $p has birth-date 1902-01-01; $p has death-date 1952-01-01; $p has age 50;
        //insert $57472 isa person has firstname "Mary" has identifier "Mary Guthrie" has surname "Guthrie" has gender "female";
        driver.execute(from(format("insert $m isa %s has stix_id \"%s\" has created %s", type, getId(), getCreated())));
    }

    //region fields
    private String name;
    private String description;
    private String created;
    private String modified;
    private String created_by_ref;
    private List<String> object_marking_refs;

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public String getDescription() {
        return description;
    }

    public void setDescription(String description) {
        this.description = description;
    }

    public String getCreated() {
        return created;
    }

    public void setCreated(String created) {
        this.created = created;
    }

    public String getModified() {
        return modified;
    }

    public void setModified(String modified) {
        this.modified = modified;
    }

    public String getCreated_by_ref() {
        return created_by_ref;
    }

    public void setCreated_by_ref(String created_by_ref) {
        this.created_by_ref = created_by_ref;
    }

    public List<String> getObject_marking_refs() {
        return object_marking_refs;
    }

    public void setObject_marking_refs(List<String> object_marking_refs) {
        this.object_marking_refs = object_marking_refs;
    }
    //endregion
}
