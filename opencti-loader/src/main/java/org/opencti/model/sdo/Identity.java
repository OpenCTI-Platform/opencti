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
        Object identity = driver.read(format("match $m isa Identity has stix_id %s; get;", prepare(getId())));
        if (identity == null) {
            String identityCreation = format("insert $m isa Identity " +
                            "has stix_id %s " +
                            "has name %s " +
                            "has identity_class %s " +
                            "has type %s " +
                            "has modified %s " +
                            "has created %s;",
                    prepare(getId()),
                    prepare(getName()),
                    prepare(getIdentity_class()),
                    prepare(getType()),
                    getModified(),
                    getCreated()
            );
            driver.write(identityCreation);
        }
    }

    private String name;
    private String identity_class;

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    private String getIdentity_class() {
        return identity_class;
    }

    public void setIdentity_class(String identity_class) {
        this.identity_class = identity_class;
    }
}
