package org.opencti.model.sdo;

import org.opencti.model.database.LoaderDriver;

import static org.opencti.model.database.BaseQuery.from;

public class MarkingDefinition extends Domain {
    @Override
    public void neo4j(LoaderDriver driver) {
        String query = "MERGE (markingDefinition:MarkingDefinition {id: $id}) " +
                "ON CREATE SET markingDefinition = {" +
                /**/"id: $id, " +
                /**/"created: $created, " +
                /**/"tlp: $tlp, " +
                /**/"statement: $statement " +
                "} " +
                "ON MATCH SET " +
                /**/"markingDefinition.created = $created, " +
                /**/"markingDefinition.tlp = $tlp, " +
                /**/"markingDefinition.statement = $statement";
        driver.execute(from(query).withParams("id", getId(),
                "created", getCreated(),
                "modified", getModified(),
                "tlp", getDefinition().getTlp(),
                "statement", getDefinition().getStatement()
        ));
    }

    private StixDefinition definition;

    public StixDefinition getDefinition() {
        return definition;
    }

    public void setDefinition(StixDefinition definition) {
        this.definition = definition;
    }
}
