package org.opencti.model;

import org.opencti.model.database.LoaderDriver;

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
    public int neo4j(LoaderDriver driver) {
        return objects.stream().map(o -> o.neo4j(driver)).mapToInt(Integer::intValue).sum();
    }

    @Override
    public int grakn(LoaderDriver driver) {
        return objects.stream().map(o -> o.grakn(driver)).mapToInt(Integer::intValue).sum();
    }
}
