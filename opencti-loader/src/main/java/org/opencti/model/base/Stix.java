package org.opencti.model.base;

import org.opencti.model.database.GraknDriver;
import org.opencti.model.sro.Relationship;

import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

public interface Stix {
    String getId();

    default void load(GraknDriver driver, Map<String, Stix> stixElements) {
        //Do nothing
    }

    default List<Relationship> extraRelations(Map<String, Stix> stixElements) {
        return new ArrayList<>();
    }

    default String getEntityName() {
        return getClass().getSimpleName();
    }

    default String getType() {
        return getEntityName().toLowerCase();
    }

    default boolean isImplemented() {
        return false;
    }

    default String prepare(String s) {
        return s != null ? "\"" + s.replace("\\", "\\\\").replaceAll("\"", "\\\\\"") + "\"" : null;
    }

    default String getCurrentTime() {
        ZonedDateTime zonedDateTime = ZonedDateTime.now();
        return zonedDateTime.format(DateTimeFormatter.ISO_LOCAL_DATE_TIME);
    }
}
