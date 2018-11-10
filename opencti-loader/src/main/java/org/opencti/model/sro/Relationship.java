package org.opencti.model.sro;

import org.opencti.model.StixBase;
import org.opencti.model.database.BaseQuery;

import java.util.ArrayList;
import java.util.List;

import static java.util.Arrays.asList;
import static org.apache.commons.text.CaseUtils.toCamelCase;
import static org.opencti.model.database.BaseQuery.from;

public class Relationship extends StixBase {

    private String parseId(String id) {
        return asList(id.split("--")).get(0);
    }

    @Override
    public List<BaseQuery> neo4j() {
        List<BaseQuery> dq = new ArrayList<>();
        String relationName = toCamelCase(getRelationship_type(), false, '-');
        String sourceType = toCamelCase(parseId(getSource_ref()), true, '-');
        String sourceName = sourceType.toLowerCase();
        String targetType = toCamelCase(parseId(getTarget_ref()), true, '-');
        String targetName = targetType.toLowerCase();

        //Create entities
        String sourceQuery = "MERGE (" + sourceName + ":" + sourceType + " {id: $sourceId}) ON CREATE SET " + sourceName + " = {id: $sourceId}";
        dq.add(from(sourceQuery).withParams("sourceId", getSource_ref()));

        String targetQuery = "MERGE (" + targetName + ":" + targetType + " {id: $targetId}) ON CREATE SET " + targetName + " = {id: $targetId}";
        dq.add(from(targetQuery).withParams("targetId", getTarget_ref()));

        //Create relation
        String relationQuery = "MATCH (" + sourceName + ":" + sourceType + " {id: $sourceId}), (" + targetName + ":" + targetType + " {id: $targetId}) " +
                "MERGE (" + sourceName + ")-[:" + relationName + " {id: $relationId, created: $created, modified: $modified} ]->(" + targetName + ")";
        dq.add(from(relationQuery).withParams(
                "sourceId", getSource_ref(),
                "targetId", getTarget_ref(),
                "relationId", getId(),
                "created", getCreated(),
                "modified", getModified()
        ));
        return dq;
    }

    @Override
    public List<BaseQuery> grakn() {
        return null;
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
