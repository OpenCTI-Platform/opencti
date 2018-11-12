package org.opencti.model.base;

import com.fasterxml.jackson.annotation.JsonSubTypes;
import com.fasterxml.jackson.annotation.JsonTypeInfo;
import org.opencti.model.sdo.*;
import org.opencti.model.sdo.container.Bundle;
import org.opencti.model.sro.Relationship;

import java.util.List;

import static java.util.Collections.singletonList;

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
public abstract class StixBase implements Stix {

    private String id;

    @Override
    public String getId() {
        return id;
    }

    public void setId(String id) {
        this.id = id;
    }

    public List<Stix> toStixElements() {
        return singletonList(this);
    }
}
