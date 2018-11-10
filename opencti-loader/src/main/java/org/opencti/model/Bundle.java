package org.opencti.model;

import org.opencti.model.database.BaseQuery;

import java.util.Collection;
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
    public List<BaseQuery> neo4j() {
        return objects.stream().map(StixBase::neo4j).flatMap(Collection::stream).collect(Collectors.toList());
    }

    @Override
    public List<BaseQuery> grakn() {
        return objects.stream().map(StixBase::grakn).flatMap(Collection::stream).collect(Collectors.toList());
    }
}
