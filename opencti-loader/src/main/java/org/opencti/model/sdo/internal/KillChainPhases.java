package org.opencti.model.sdo.internal;

import org.opencti.model.base.Stix;
import org.opencti.model.database.GraknDriver;

import java.util.Map;
import java.util.UUID;

import static java.lang.String.format;

public class KillChainPhases implements Stix {

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
    public void load(GraknDriver driver, Map<String, Stix> stixElements) {
        //Must have same external_id / url  and source_name
        StringBuilder killChainIdQuery = new StringBuilder("$ref isa Kill-Chain-Phase ");
        killChainIdQuery.append(format("has phase_name %s ", prepare(getPhase_name())));
        killChainIdQuery.append(format("has kill_chain_name %s ", prepare(getKill_chain_name())));
        Object killChainRef = driver.read("match " + killChainIdQuery.toString() + "; get;");
        if (killChainRef == null) {
            StringBuilder refBuilder = new StringBuilder();
            refBuilder.append("insert $ref isa Kill-Chain-Phase");
            refBuilder.append(" has stix_id ").append(prepare(getId()));
            refBuilder.append(" has phase_name ").append(prepare(getPhase_name()));
            refBuilder.append(" has kill_chain_name ").append(prepare(getKill_chain_name()));
            refBuilder.append(" has created ").append(getCurrentTime());
            refBuilder.append(" has modified ").append(getCurrentTime());
            refBuilder.append(" has created_at ").append(getCurrentTime());
            refBuilder.append(" has updated_at ").append(getCurrentTime());
            refBuilder.append(";");
            driver.write(refBuilder.toString());
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
