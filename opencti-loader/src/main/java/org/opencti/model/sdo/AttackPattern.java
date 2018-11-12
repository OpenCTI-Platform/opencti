package org.opencti.model.sdo;

import org.opencti.model.StixBase;
import org.opencti.model.StixElement;
import org.opencti.model.database.GraknRelation;
import org.opencti.model.database.LoaderDriver;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import static java.lang.String.format;
import static org.opencti.model.database.BaseQuery.from;
import static org.opencti.model.utils.StixUtils.prepare;

public class AttackPattern extends Domain {
    @Override
    public String getEntityName() {
        return "Attack-Pattern";
    }

    @Override
    public boolean isImplemented() {
        return true;
    }

    @Override
    public void grakn(LoaderDriver driver, Map<String, StixBase> stixElements) {
        Object attackPattern = driver.execute(from(format("match $m isa %s has stix_id %s; get;", getEntityName(), prepare(getId()))));
        if (attackPattern == null) { //Only create if the attackPattern doesn't exists
            StringBuilder query = new StringBuilder();
            query.append("insert $m isa Attack-Pattern has stix_id ").append(prepare(getId()));
            query.append(" has name ").append(prepare(getName()));
            query.append(" has type ").append(prepare(getType()));
            if (getLabelChain() != null) query.append(getLabelChain());
            if (getDescription() != null) query.append(" has description ").append(prepare(getDescription()));
            query.append(" has revoked ").append(getRevoked());
            query.append(" has created ").append(getCreated());
            query.append(";");
            driver.execute(from(query.toString()));
        }
    }

    private String name;
    private String description;
    private List<KillChainPhases> kill_chain_phases = new ArrayList<>();

    @Override
    public List<StixElement> toStixElements() {
        List<StixElement> stixElements = super.toStixElements();
        stixElements.addAll(getKill_chain_phases());
        return stixElements;
    }

    @Override
    public List<GraknRelation> extraRelations(Map<String, StixElement> stixElements) {
        List<GraknRelation> graknRelations = super.extraRelations(stixElements);
        graknRelations.addAll(getKill_chain_phases().stream()
                .map(r -> new GraknRelation(this, r, "phase_belonging", "kill_chain_phase", "kill_chain_phases"))
                .collect(Collectors.toList()));
        return graknRelations;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public String getDescription() {
        return description;
    }

    public void setDescription(String description) {
        this.description = description;
    }

    public List<KillChainPhases> getKill_chain_phases() {
        return kill_chain_phases;
    }

    public void setKill_chain_phases(List<KillChainPhases> kill_chain_phases) {
        this.kill_chain_phases = kill_chain_phases;
    }
}
