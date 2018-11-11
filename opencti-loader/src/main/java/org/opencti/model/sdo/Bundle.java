package org.opencti.model.sdo;

import org.opencti.model.StixBase;
import org.opencti.model.StixElement;

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
    public List<StixElement> toStixElements() {
        return objects.stream().map(StixBase::toStixElements).flatMap(List::stream).collect(Collectors.toList());
    }
}
