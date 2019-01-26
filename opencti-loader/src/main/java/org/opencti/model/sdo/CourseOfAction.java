package org.opencti.model.sdo;

import org.opencti.model.base.Stix;
import org.opencti.model.database.GraknDriver;
import org.opencti.model.sdo.container.Domain;

import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.util.Map;

import static java.lang.String.format;

public class CourseOfAction extends Domain {
    @Override
    public String getEntityName() {
        return "Course-Of-Action";
    }

    @Override
    public boolean isImplemented() {
        return true;
    }

    @Override
    public void load(GraknDriver driver, Map<String, Stix> stixElements) {
        Object CourseOfAction = driver.read(format("match $m isa %s has stix_id %s; get;", getEntityName(), prepare(getId())));
        if (CourseOfAction == null) { //Only create if the CourseOfAction doesn't exists
            StringBuilder query = new StringBuilder();
            query.append("insert $m isa Course-Of-Action has stix_id ").append(prepare(getId()));
            query.append(" has name ").append(prepare(getName()));
            query.append(" has name_lowercase ").append(prepare(getName().toLowerCase()));
            query.append(" has type ").append(prepare(getType()));
            if (getLabelChain() != null) query.append(getLabelChain());
            if (getDescription() != null) query.append(" has description ").append(prepare(getDescription()));
            if (getDescription() != null) query.append(" has description_lowercase ").append(prepare(getDescription().toLowerCase()));
            query.append(" has revoked ").append(getRevoked());
            query.append(" has created ").append(getCreated());
            query.append(" has modified ").append(getModified());
            query.append(" has created_at ").append(getCurrentTime());
            query.append(" has updated_at ").append(getCurrentTime());
            query.append(";");
            driver.write(query.toString());
        }
    }

    private String name;
    private String description;

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
}
