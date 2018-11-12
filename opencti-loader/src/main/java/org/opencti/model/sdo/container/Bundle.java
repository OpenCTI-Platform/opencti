package org.opencti.model.sdo.container;

import org.opencti.model.base.StixBase;
import org.opencti.model.base.Stix;

import java.util.List;
import java.util.stream.Collectors;

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
    public List<Stix> toStixElements() {
        return objects.stream().map(StixBase::toStixElements).flatMap(List::stream).collect(Collectors.toList());
    }
}
