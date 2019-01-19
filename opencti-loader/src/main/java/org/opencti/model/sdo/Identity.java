package org.opencti.model.sdo;

import org.opencti.model.base.Stix;
import org.opencti.model.database.GraknDriver;
import org.opencti.model.sdo.container.Domain;

import java.util.Map;

import static java.lang.String.format;

public class Identity extends Domain {

    @Override
    public boolean isImplemented() {
        return true;
    }

    @Override
    public void load(GraknDriver driver, Map<String, Stix> stixElements) {
        Object identity = driver.read(format("match $m isa Organization has stix_id %s; get;", prepare(getId())));
        if (identity == null) {
            String identityCreation = format("insert $m isa Organization " +
                            "has stix_id %s " +
                            "has name %s " +
                            "has type %s " +
                            "has created %s " +
                            "has modified %s " +
                            "has created_at %s " +
                            "has updated_at %s;",
                    prepare(getId()).replace("identity", "organization"),
                    prepare(getName()),
                    "\"organization\"",
                    getCreated(),
                    getModified(),
                    getCurrentTime(),
                    getCurrentTime()
            );
            driver.write(identityCreation);
        }
    }

    private String name;

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }
}
