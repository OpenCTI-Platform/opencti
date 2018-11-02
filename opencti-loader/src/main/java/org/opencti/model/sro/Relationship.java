package org.opencti.model.sro;

import org.opencti.model.StixBase;

import java.util.List;

import static java.util.Arrays.asList;
import static org.apache.commons.text.CaseUtils.toCamelCase;
import static org.opencti.OpenCTI.driver;

public class Relationship extends StixBase {

    private String parseId(String id) {
        return asList(id.split("--")).get(0);
    }

    @Override
    public void load() {
        String relationName = toCamelCase(getRelationship_type(), false, '-');
        String sourceType = toCamelCase(parseId(getSource_ref()), true, '-');
        String sourceName = sourceType.toLowerCase();
        String targetType = toCamelCase(parseId(getTarget_ref()), true, '-');
        String targetName = targetType.toLowerCase();

        //Create entities
        String sourceQuery = "MERGE (" + sourceName + ":" + sourceType + " {id: $sourceId}) ON CREATE SET " + sourceName + " = {id: $sourceId}";
        execute(driver, sourceQuery, "sourceId", getSource_ref());

        String targetQuery = "MERGE (" + targetName + ":" + targetType + " {id: $targetId}) ON CREATE SET " + targetName + " = {id: $targetId}";
        execute(driver, targetQuery, "targetId", getTarget_ref());

        //Create relation
        String relationQuery = "MATCH (" + sourceName + ":" + sourceType + " {id: $sourceId}), (" + targetName + ":"+ targetType + " {id: $targetId}) " +
                "MERGE (" + sourceName + ")-[:" + relationName + " {id: $relationId, created: $created, modified: $modified} ]->(" + targetName + ")";
        execute(driver, relationQuery,
                "sourceId", getSource_ref(),
                "targetId", getTarget_ref(),
                "relationId", getId(),
                "created", getCreated(),
                "modified", getModified()
        );
    }

    private String created_by_ref;
    private List<String> object_marking_refs;
    private String source_ref;
    private String relationship_type;
    private String target_ref;
    private String modified;
    private String created;

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

    public String getSource_ref() {
        return source_ref;
    }

    public void setSource_ref(String source_ref) {
        this.source_ref = source_ref;
    }

    public String getRelationship_type() {
        return relationship_type;
    }

    public void setRelationship_type(String relationship_type) {
        this.relationship_type = relationship_type;
    }

    public String getTarget_ref() {
        return target_ref;
    }

    public void setTarget_ref(String target_ref) {
        this.target_ref = target_ref;
    }

    public String getModified() {
        return modified;
    }

    public void setModified(String modified) {
        this.modified = modified;
    }

    public String getCreated() {
        return created;
    }

    public void setCreated(String created) {
        this.created = created;
    }
}
