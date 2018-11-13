package org.opencti.mapping;

import org.opencti.model.base.Stix;

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

/*






  "mappings": [
    {
      "from": "Attack-Pattern",
      "to": [
        {
          "entity": "Identity",
          "relations": [
            {
              "name": "targets",
              "role": {
                "from": "source",
                "to": "target"
              }
            }
          ]
        },
        {
          "entity": "Vulnerability",
          "relations": [
            {
              "name": "targets",
              "role": {
                "from": "source",
                "to": "target"
              }
            }
          ]
        },
        {
          "entity": "Malware",
          "relations": [
            {
              "name": "uses",
              "role": {
                "from": "user",
                "to": "usage"
              }
            }
          ]
        },
        {
          "entity": "Tool",
          "relations": [
            {
              "name": "uses",
              "role": {
                "from": "user",
                "to": "usage"
              }
            }
          ]
        },
        {
          "entity": "Attack-Pattern",
          "relations": [
            {
              "name": "related-to",
              "role": {
                "from": "relate_from",
                "to": "relate_to"
              }
            }
          ]
        }
      ]
    }
  ]
 */
