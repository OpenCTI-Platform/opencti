package org.opencti.model;

import com.fasterxml.jackson.annotation.JsonSubTypes;
import com.fasterxml.jackson.annotation.JsonTypeInfo;
import org.opencti.OpenCTI;
import org.opencti.model.database.BaseQuery;
import org.opencti.model.database.Neo4jDriver;
import org.opencti.model.sdo.*;
import org.opencti.model.sro.Relationship;

import java.util.List;

@JsonTypeInfo(
        use = JsonTypeInfo.Id.NAME,
        property = "type")
@JsonSubTypes({
        @JsonSubTypes.Type(value = Bundle.class, name = "bundle"),
        @JsonSubTypes.Type(value = AttackPattern.class, name = "attack-pattern"),
        @JsonSubTypes.Type(value = CourseOfAction.class, name = "course-of-action"),
        @JsonSubTypes.Type(value = Identity.class, name = "identity"),
        @JsonSubTypes.Type(value = IntrusionSet.class, name = "intrusion-set"),
        @JsonSubTypes.Type(value = Malware.class, name = "malware"),
        @JsonSubTypes.Type(value = MarkingDefinition.class, name = "marking-definition"),
        @JsonSubTypes.Type(value = Tool.class, name = "tool"),
        @JsonSubTypes.Type(value = Relationship.class, name = "relationship"),
})
public abstract class StixBase {
    private String id;

    protected String getId() {
        return id;
    }

    public void setId(String id) {
        this.id = id;
    }

    public List<BaseQuery> getQueries() {
        return OpenCTI.driver instanceof Neo4jDriver ? neo4j() : grakn();
    }

    public abstract List<BaseQuery> neo4j();

    public abstract List<BaseQuery> grakn();
}
