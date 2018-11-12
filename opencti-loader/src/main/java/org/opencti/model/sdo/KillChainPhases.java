package org.opencti.model.sdo;

import org.opencti.model.StixBase;
import org.opencti.model.StixElement;
import org.opencti.model.database.LoaderDriver;

import java.util.Map;
import java.util.UUID;

import static java.lang.String.format;
import static org.opencti.model.database.BaseQuery.from;
import static org.opencti.model.utils.StixUtils.prepare;

public class KillChainPhases implements StixElement {

    @Override
    public String getEntityName() {
        return "Kill-Chain-Phase";
    }

    @Override
    public boolean isImplemented() {
        return true;
    }

    @SuppressWarnings("StringBufferReplaceableByString")
    @Override
    public void grakn(LoaderDriver driver, Map<String, StixBase> stixElements) {
        //Must have same external_id / url  and source_name
        StringBuilder killChainIdQuery = new StringBuilder("$ref isa Kill-Chain-Phase ");
        killChainIdQuery.append(format("has phase_name %s ", prepare(getPhase_name())));
        killChainIdQuery.append(format("has kill_chain_name %s ", prepare(getKill_chain_name())));
        Object killChainRef = driver.execute(from("match " + killChainIdQuery.toString() + "; get;"));
        if (killChainRef == null) {
            StringBuilder refBuilder = new StringBuilder();
            refBuilder.append("insert $ref isa Kill-Chain-Phase");
            refBuilder.append(" has stix_id ").append(prepare(getId()));
            refBuilder.append(" has phase_name ").append(prepare(getPhase_name()));
            refBuilder.append(" has kill_chain_name ").append(prepare(getKill_chain_name()));
            refBuilder.append(";");
            driver.execute(from(refBuilder.toString()));
        }
    }

    private String phase_name;
    private String kill_chain_name;

    public String getPhase_name() {
        return phase_name;
    }

    public void setPhase_name(String phase_name) {
        this.phase_name = phase_name;
    }

    public String getKill_chain_name() {
        return kill_chain_name;
    }

    public void setKill_chain_name(String kill_chain_name) {
        this.kill_chain_name = kill_chain_name;
    }

    @Override
    public String getId() {
        String key = getPhase_name() + "-" + getKill_chain_name();
        return "kill-chain-phase--" + UUID.nameUUIDFromBytes(key.getBytes());
    }
}
