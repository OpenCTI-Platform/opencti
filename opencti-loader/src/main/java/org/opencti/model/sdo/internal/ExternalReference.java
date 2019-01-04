package org.opencti.model.sdo.internal;

import org.opencti.model.base.Stix;
import org.opencti.model.database.GraknDriver;

import java.util.Map;
import java.util.UUID;

import static java.lang.String.format;

public class ExternalReference implements Stix {

    private String external_id;
    private String url;
    private String source_name;
    private String description;

    @Override
    public String getEntityName() {
        return "External-Reference";
    }

    @Override
    public boolean isImplemented() {
        return true;
    }

    @Override
    public void load(GraknDriver driver, Map<String, Stix> stixElements) {
        //Must have same external_id / url  and source_name
        StringBuilder externalIdQuery = new StringBuilder("$ref isa External-Reference ");
        if (getExternal_id() != null)
            externalIdQuery.append(format("has external_id %s ", prepare(getExternal_id())));
        externalIdQuery.append(format("has source_name %s ", prepare(getSource_name())));
        externalIdQuery.append(format("has url %s ", prepare(getUrl())));
        Object externalRef = driver.read("match " + externalIdQuery.toString() + "; get;");

        if (externalRef == null) {
            StringBuilder refBuilder = new StringBuilder();
            refBuilder.append("insert $ref isa External-Reference")
                    .append(" has stix_id ").append(prepare(getId()));
            if (getExternal_id() != null)
                refBuilder.append(" has external_id ").append(prepare(getExternal_id()));
            refBuilder.append(" has source_name ").append(prepare(getSource_name()));
            if (getDescription() != null)
                refBuilder.append(" has description ").append(prepare(getDescription()));
            refBuilder.append(" has url ").append(prepare(getUrl()));
            refBuilder.append(" has created ").append(getCurrentTime());
            refBuilder.append(" has modified ").append(getCurrentTime());
            refBuilder.append(" has created_at ").append(getCurrentTime());
            refBuilder.append(" has updated_at ").append(getCurrentTime());
            refBuilder.append(";");
            driver.write(refBuilder.toString());
        }
    }

    @Override
    public String getId() {
        String key = getSource_name() + "-" + getUrl();
        return "external-reference--" + UUID.nameUUIDFromBytes(key.getBytes());
    }

    public String getExternal_id() {
        return external_id;
    }

    public void setExternal_id(String external_id) {
        this.external_id = external_id;
    }

    public String getUrl() {
        return url;
    }

    public void setUrl(String url) {
        this.url = url;
    }

    public String getSource_name() {
        return source_name;
    }

    public void setSource_name(String source_name) {
        this.source_name = source_name;
    }

    public String getDescription() {
        return description;
    }

    public void setDescription(String description) {
        this.description = description;
    }
}
