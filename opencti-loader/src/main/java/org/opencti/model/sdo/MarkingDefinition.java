package org.opencti.model.sdo;

import org.opencti.model.base.Stix;
import org.opencti.model.database.GraknDriver;
import org.opencti.model.sdo.container.Domain;
import org.opencti.model.sdo.internal.StixDefinition;
import org.opencti.model.sro.Relationship;

import java.util.List;
import java.util.Map;

import static java.lang.String.format;

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
    public void load(GraknDriver driver, Map<String, Stix> stixElements) {
        Object marking = driver.read(format("match $m isa Marking-Definition has stix_id %s; get;", prepare(getId())));
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
            driver.write(markingCreation);
        }
    }

    @Override
    public List<Relationship> extraRelations(Map<String, Stix> stixElements) {
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
