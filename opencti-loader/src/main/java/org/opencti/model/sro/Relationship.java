package org.opencti.model.sro;

import org.opencti.model.base.Stix;
import org.opencti.model.database.GraknDriver;
import org.opencti.model.sdo.container.Domain;

import java.util.Map;
import java.util.UUID;

import static java.lang.String.format;

public class Relationship extends Domain {
    @Override
    public boolean isImplemented() {
        return true;
    }

    @Override
    public String getEntityName() {
        return "relationship";
    }

    @SuppressWarnings("unused")
    public Relationship() {
        //Default constructor
    }

    public Relationship(Stix from, Stix to, String fromRole, String toRole, String relationName) {
        this.source_ref = from.getId();
        this.target_ref = to.getId();
        this.fromRole = fromRole;
        this.toRole = toRole;
        this.relationship_type = relationName;
    }

    @Override
    public void load(GraknDriver driver, Map<String, Stix> stixElements) {
        //Create relation
        Stix from = stixElements.get(getSource_ref());
        if (from == null) throw new RuntimeException("Cannot find " + getSource_ref() + " in the loader");
        Stix to = stixElements.get(getTarget_ref());
        if (to == null) throw new RuntimeException("Cannot find " + getTarget_ref() + " in the loader");

        //Ignoring some specific relations
        boolean fromRevokedBy = from instanceof Relationship
                && ((Relationship) from).getRelationship_type().equals("revoked-by");
        boolean toRevokedBy = to instanceof Relationship
                && ((Relationship) to).getRelationship_type().equals("revoked-by");
        boolean currentRevokedBy = "revoked-by".equals(getRelationship_type());
        if (fromRevokedBy || toRevokedBy || currentRevokedBy) {
            return;
        }

        String fromRole = getFromRole();
        String toRole = getToRole();
        if (fromRole == null || toRole == null) {
            RolePair pair = driver.resolveRelationRoles(getRelationship_type(), from.getEntityName(), to.getEntityName());
            fromRole = pair.getFrom();
            toRole = pair.getTo();
        }
        String getRelation = format("match $from isa %s " +
                        "has stix_id %s; " +
                        "$to isa %s has stix_id %s; " +
                        "(%s: $from, %s: $to) isa %s; " +
                        "offset 0; limit 1; get;",
                from.getEntityName(),
                prepare(from.getId()),
                to.getEntityName(),
                prepare(to.getId()),
                fromRole,
                toRole,
                getRelationship_type());
        Object relation = driver.read(getRelation);

        if (relation == null) {
            String relationCreation = format("match $from isa %s " +
                            "has stix_id %s; " +
                            "$to isa %s has stix_id %s; " +
                            "insert (%s: $from, %s: $to) " +
                            "has stix_id %s" +
                            "isa %s;",
                    from.getEntityName(),
                    prepare(from.getId()),
                    to.getEntityName(),
                    prepare(to.getId()),
                    fromRole,
                    toRole,
                    prepare(getId()),
                    getRelationship_type());
            driver.write(relationCreation);
        }
    }

    private String id;
    private String relationship_type;
    private String source_ref;
    private String target_ref;
    //Private fields
    private String fromRole;
    private String toRole;
    //End private fields

    public String getId() {
        if (id == null) {
            return UUID.nameUUIDFromBytes((getSource_ref() + "-" + getTarget_ref()).getBytes()).toString();
        }
        return id;
    }

    public void setId(String id) {
        this.id = id;
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
}
