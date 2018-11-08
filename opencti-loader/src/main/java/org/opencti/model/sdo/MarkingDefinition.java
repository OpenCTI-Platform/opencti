package org.opencti.model.sdo;

import static org.opencti.OpenCTI.driver;

public class MarkingDefinition extends Domain {
    @Override
    public void load() {
        String query = "MERGE (markingDefinition:MarkingDefinition {id: $id}) " +
                "ON CREATE SET markingDefinition = {" +
                /**/"id: $id, " +
                /**/"name: $name, " +
                /**/"description: $description, " +
                /**/"created: $created, " +
                /**/"tlp: $tlp, " +
                /**/"statement: $statement " +
                "} "+
                "ON MATCH SET " +
                /**/"markingDefinition.name = $name, " +
                /**/"markingDefinition.description = $description, " +
                /**/"markingDefinition.created = $created, " +
                /**/"markingDefinition.tlp = $tlp, " +
                /**/"markingDefinition.statement = $statement";
        execute(driver, query, "id", getId(),
                "name", getName(),
                "description", getDescription(),
                "created", getCreated(),
                "modified", getModified(),
                "tlp", getDefinition().getTlp(),
                "statement", getDefinition().getStatement()
        );
    }

    private StixDefinition definition;

    public StixDefinition getDefinition() {
        return definition;
    }

    public void setDefinition(StixDefinition definition) {
        this.definition = definition;
    }
}
