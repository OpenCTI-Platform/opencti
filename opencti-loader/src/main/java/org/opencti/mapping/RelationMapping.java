package org.opencti.mapping;

public class RelationMapping {

    private String relation;
    private String from;
    private String to;

    public String getRelation() {
        return relation;
    }

    public void setRelation(String relation) {
        this.relation = relation;
    }

    public String getFrom() {
        return from;
    }

    public void setFrom(String from) {
        this.from = from;
    }

    public String getTo() {
        return to;
    }

    public void setTo(String to) {
        this.to = to;
    }

    @Override
    public String toString() {
        return "{from: " + from + ", to=: " + to + "}";
    }
}
