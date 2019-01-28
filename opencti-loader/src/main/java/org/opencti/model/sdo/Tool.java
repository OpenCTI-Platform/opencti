package org.opencti.model.sdo;

import org.opencti.model.base.Stix;
import org.opencti.model.database.GraknDriver;
import org.opencti.model.sdo.container.Domain;

import java.util.Map;

import static java.lang.String.format;

public class Tool extends Domain {
    @Override
    public boolean isImplemented() {
        return true;
    }

    @Override
    public void load(GraknDriver driver, Map<String, Stix> stixElements) {
        Object tool = driver.read(format("match $m isa Marking-Definition has stix_id %s; get;", prepare(getId())));
        if (tool == null) {
            StringBuilder query = new StringBuilder();
            query.append("insert $m isa Tool has stix_id ").append(prepare(getId()));
            query.append(" has name ").append(prepare(getName()));
            query.append(" has name_lowercase ").append(prepare(getName().toLowerCase()));
            query.append(" has alias ").append(prepare(""));
            query.append(" has alias_lowercase").append(prepare(""));
            query.append(" has type ").append(prepare(getType()));
            if (getLabelChain() != null) query.append(getLabelChain());
            if (getDescription() != null) query.append(" has description ").append(prepare(getDescription()));
            if (getDescription() != null) query.append(" has description_lowercase ").append(prepare(getDescription().toLowerCase()));
            if (getTool_version() != null) query.append(" has tool_version ").append(prepare(getTool_version()));
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
    private String tool_version;

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

    public String getTool_version() {
        return tool_version;
    }

    public void setTool_version(String tool_version) {
        this.tool_version = tool_version;
    }
    //endregion
}
