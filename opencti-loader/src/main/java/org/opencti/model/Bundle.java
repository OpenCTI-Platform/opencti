package org.opencti.model;

import java.util.List;

public class Bundle extends StixBase {
    private String spec_version;
    private List<StixBase> objects;

    public String getSpec_version() {
        return spec_version;
    }

    public void setSpec_version(String spec_version) {
        this.spec_version = spec_version;
    }

    public List<StixBase> getObjects() {
        return objects;
    }

    public void setObjects(List<StixBase> objects) {
        this.objects = objects;
    }

    @Override
    public void load() {
        objects.forEach(StixBase::load);
    }
}
