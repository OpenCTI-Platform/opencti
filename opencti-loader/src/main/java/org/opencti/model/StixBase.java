package org.opencti.model;

import com.fasterxml.jackson.annotation.JsonSubTypes;
import com.fasterxml.jackson.annotation.JsonTypeInfo;
import org.opencti.model.database.LoaderDriver;
import org.opencti.model.sdo.*;
import org.opencti.model.sro.Relationship;

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

    public abstract void neo4j(LoaderDriver driver);

    public abstract void grakn(LoaderDriver driver);
}
