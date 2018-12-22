package org.opencti.model.sdo;

import org.opencti.model.base.Stix;
import org.opencti.model.database.GraknDriver;
import org.opencti.model.sdo.container.Domain;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import static java.lang.String.format;

public class IntrusionSet extends Domain {
    @Override
    public String getEntityName() {
        return "Intrusion-Set";
    }

    @Override
    public boolean isImplemented() {
        return true;
    }

    @Override
    public void load(GraknDriver driver, Map<String, Stix> stixElements) {
        Object IntrusionSet = driver.read(format("match $m isa %s has stix_id %s; get;", getEntityName(), prepare(getId())));
        if (IntrusionSet == null) { //Only create if the IntrusionSet doesn't exists
            StringBuilder query = new StringBuilder();
            query.append("insert $m isa Intrusion-Set has stix_id ").append(prepare(getId()));
            query.append(" has name ").append(prepare(getName()));
            if (getDescription() != null) query.append(" has description ").append(prepare(getDescription()));
            if (getLabelChain() != null) query.append(getLabelChain());
            if (getAliasChain() != null) query.append(getAliasChain());
            query.append(" has type ").append(prepare(getType()));
            query.append(" has revoked ").append(getRevoked());
            query.append(" has created ").append(getCreated());
            query.append(" has modified ").append(getModified());
            query.append(" has created_at ").append(getCurrentTime());
            query.append(" has updated_at ").append(getCurrentTime());
            if (getFirst_seen() != null) query.append(" has first_seen ").append(getFirst_seen());
            if (getLast_seen() != null) query.append(" has last_seen ").append(getLast_seen());
            if (getGoal() != null) query.append(" has goal ").append(getGoal());
            if (getResource_level() != null) query.append(" has resource_level ").append(getResource_level());
            if (getPrimary_motivation() != null)
                query.append(" has primary_motivation ").append(getPrimary_motivation());
            if (getSecondary_motivation() != null)
                query.append(" has secondary_motivation ").append(getSecondary_motivation());
            query.append(";");
            driver.write(query.toString());
        }
    }

    private String getAliasChain() {
        return getAliases().size() > 0 ? " " + getAliases().stream().map(value -> format("has alias %s", prepare(value)))
                .collect(Collectors.joining(" ")) : null;
    }

    private String name;
    private String description;
    private String first_seen;
    private String last_seen;
    private String goal;
    private String resource_level;
    private String primary_motivation;
    private String secondary_motivation;
    private List<String> aliases = new ArrayList<>();

    //region fields
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

    public List<String> getAliases() {
        return aliases;
    }

    public void setAliases(List<String> aliases) {
        this.aliases = aliases;
    }

    public String getFirst_seen() {
        return first_seen;
    }

    public void setFirst_seen(String first_seen) {
        this.first_seen = first_seen;
    }

    public String getLast_seen() {
        return last_seen;
    }

    public void setLast_seen(String last_seen) {
        this.last_seen = last_seen;
    }

    public String getGoal() {
        return goal;
    }

    public void setGoal(String goal) {
        this.goal = goal;
    }

    public String getResource_level() {
        return resource_level;
    }

    public void setResource_level(String resource_level) {
        this.resource_level = resource_level;
    }

    public String getPrimary_motivation() {
        return primary_motivation;
    }

    public void setPrimary_motivation(String primary_motivation) {
        this.primary_motivation = primary_motivation;
    }

    public String getSecondary_motivation() {
        return secondary_motivation;
    }

    public void setSecondary_motivation(String secondary_motivation) {
        this.secondary_motivation = secondary_motivation;
    }
    //endregion
}
