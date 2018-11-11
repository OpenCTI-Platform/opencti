package org.opencti.model.sdo;

import org.opencti.model.StixBase;
import org.opencti.model.StixElement;
import org.opencti.model.database.GraknRelation;
import org.opencti.model.database.LoaderDriver;

import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;

import static java.lang.String.format;
import static org.opencti.model.database.BaseQuery.from;
import static org.opencti.model.utils.StixUtils.prepare;

public class MarkingDefinition extends Domain {

    @Override
    public boolean isImplemented() {
        return true;
    }

    @Override
    public String getEntityName() {
        return "Marking-Definition";
    }

    @Override
    public void neo4j(LoaderDriver driver, Map<String, StixBase> stixElements) {
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

    @Override
    public void grakn(LoaderDriver driver, Map<String, StixBase> stixElements) {
        AtomicInteger nbRequests = new AtomicInteger();
        Object marking = driver.execute(from(format("match $m isa Marking-Definition has stix_id %s; get;", prepare(getId()))));
        nbRequests.getAndIncrement();
        if (marking == null) {
            String definitionType = prepare(getDefinition_type());
            String markingCreation = format("insert $m isa Marking-Definition " +
                            "has stix_id %s " +
                            "has type %s " +
                            "has definition %s " +
                            "has created %s " +
                            "has definition_type %s;",
                    prepare(getId()),
                    prepare(getType()),
                    prepare("tlp".equals(definitionType) ? getDefinition().getTlp() : getDefinition().getStatement()),
                    getCreated(),
                    prepare(definitionType));
            driver.execute(from(markingCreation));
            nbRequests.getAndIncrement();
        }
    }

    @Override
    public List<GraknRelation> extraRelations(Map<String, StixElement> stixElements) {
        return createCreatorRef(stixElements);
    }

    private StixDefinition definition;
    private String definition_type;

    public String getDefinition_type() {
        return definition_type;
    }

    public void setDefinition_type(String definition_type) {
        this.definition_type = definition_type;
    }

    public StixDefinition getDefinition() {
        return definition;
    }

    public void setDefinition(StixDefinition definition) {
        this.definition = definition;
    }
}
