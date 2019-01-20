package org.opencti.model.sdo.container;

import org.opencti.model.base.StixBase;
import org.opencti.model.base.Stix;
import org.opencti.model.sdo.internal.ExternalReference;
import org.opencti.model.sro.Relationship;

import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import static java.lang.String.format;

public abstract class Domain extends StixBase {

    private List<Relationship> createMarkingRefs(Map<String, Stix> stixElements) {
        return getObject_marking_refs().stream().map(marking -> {
            Stix markingStix = stixElements.get(marking);
            if (markingStix == null) throw new RuntimeException("Cant find marking " + marking);
            return new Relationship(this, markingStix, "so", "marking", "object_marking_refs");
        }).collect(Collectors.toList());
    }

    protected List<Relationship> createCreatorRef(Map<String, Stix> stixElements) {
        List<Relationship> relations = new ArrayList<>();
        /*if (getCreated_by_ref() != null) {
            Stix stixCreator = stixElements.get(getCreated_by_ref());
            if (stixCreator == null) throw new RuntimeException("Cant find identity " + getCreated_by_ref());
            relations.add(new Relationship(this, stixCreator, "so", "creator", "created_by_ref"));
        }*/
        return relations;
    }

    protected String getLabelChain() {
        return getLabels().size() > 0 ? " " + getLabels().stream().map(value -> format("has stix_label %s", prepare(value)))
                .collect(Collectors.joining(" ")) : null;
    }

    @Override
    public List<Stix> toStixElements() {
        List<Stix> elements = new ArrayList<>();
        elements.add(this);
        List<ExternalReference> externalRefs = getExternal_references().stream()
                .filter(f -> f.getUrl() != null && f.getSource_name() != null)
                .collect(Collectors.toList());
        elements.addAll(externalRefs);
        return elements;
    }

    @Override
    public List<Relationship> extraRelations(Map<String, Stix> stixElements) {
        List<Relationship> extraQueries = new ArrayList<>();
        //External refs
        extraQueries.addAll(createExternalRef());
        //Create the created_ref
        extraQueries.addAll(createCreatorRef(stixElements));
        //object_marking_refs
        extraQueries.addAll(createMarkingRefs(stixElements));
        return extraQueries;
    }

    private List<Relationship> createExternalRef() {
        return getExternal_references().stream()
                .filter(r -> r.getUrl() != null && r.getSource_name() != null)
                .map(r -> new Relationship(this, r, "so", "external_reference", "external_references"))
                .collect(Collectors.toList());
    }

    private String created;
    private String modified;
    private boolean revoked = false;
    private String created_by_ref;
    private List<String> labels = new ArrayList<>();
    private List<String> object_marking_refs = new ArrayList<>();
    private List<ExternalReference> external_references = new ArrayList<>();

    //region fields
    public List<String> getLabels() {
        return labels;
    }

    public void setLabels(List<String> labels) {
        this.labels = labels;
    }

    public String getCreated() {
        ZonedDateTime zonedDateTime = ZonedDateTime.parse(created);
        return zonedDateTime.format(DateTimeFormatter.ISO_LOCAL_DATE_TIME);
    }

    public void setCreated(String created) {
        this.created = created;
    }

    public String getModified() {
        ZonedDateTime zonedDateTime = ZonedDateTime.parse(modified);
        return zonedDateTime.format(DateTimeFormatter.ISO_LOCAL_DATE_TIME);
    }

    public void setModified(String modified) {
        this.modified = modified;
    }

    public boolean getRevoked() {
        return revoked;
    }

    public void setRevoked(Boolean revoked) {
        this.revoked = revoked;
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

    public List<ExternalReference> getExternal_references() {
        return external_references;
    }

    public void setExternal_references(List<ExternalReference> external_references) {
        this.external_references = external_references;
    }
    //endregion
}
