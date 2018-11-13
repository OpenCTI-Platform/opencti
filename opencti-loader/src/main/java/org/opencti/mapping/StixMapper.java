package org.opencti.mapping;

import java.util.List;
import java.util.Map;
import java.util.function.Function;
import java.util.stream.Collectors;

public class StixMapper {
    private List<RelationMapping> mappings;

    public List<RelationMapping> getMappings() {
        return mappings;
    }

    public void setMappings(List<RelationMapping> mappings) {
        this.mappings = mappings;
    }

    public Map<String, RelationMapping> mappings() {
        return mappings.stream().collect(Collectors.toMap(RelationMapping::getRelation, Function.identity()));
    }
}