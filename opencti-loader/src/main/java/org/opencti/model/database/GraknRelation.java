package org.opencti.model.database;

import org.opencti.model.StixBase;
import org.opencti.model.StixElement;

public class GraknRelation {
    private StixElement from;
    private StixElement to;
    private String fromRole;
    private String toRole;
    private String relationName;

    public GraknRelation(StixElement from, StixElement to, String fromRole, String toRole, String relationName) {
        this.from = from;
        this.to = to;
        this.fromRole = fromRole;
        this.toRole = toRole;
        this.relationName = relationName;
    }

    public StixElement getFrom() {
        return from;
    }

    public void setFrom(StixBase from) {
        this.from = from;
    }

    public StixElement getTo() {
        return to;
    }

    public void setTo(StixBase to) {
        this.to = to;
    }

    public String getFromRole() {
        return fromRole;
    }

    public void setFromRole(String fromRole) {
        this.fromRole = fromRole;
    }

    public String getToRole() {
        return toRole;
    }

    public void setToRole(String toRole) {
        this.toRole = toRole;
    }

    public String getRelationName() {
        return relationName;
    }

    public void setRelationName(String relationName) {
        this.relationName = relationName;
    }
}
