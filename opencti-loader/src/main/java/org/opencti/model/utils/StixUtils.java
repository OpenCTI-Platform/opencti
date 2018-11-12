package org.opencti.model.utils;

import org.opencti.model.database.GraknRelation;
import org.opencti.model.database.LoaderDriver;

import static java.lang.String.format;
import static org.opencti.model.database.BaseQuery.from;

public class StixUtils {

    public static void createGraknRelation(LoaderDriver driver, GraknRelation r) {
        //Create relation
        String getRelation = format("match $from isa %s has stix_id %s; $to isa %s has stix_id %s; (%s: $from, %s: $to) isa %s; offset 0; limit 1; get;",
                r.getFrom().getEntityName(),
                prepare(r.getFrom().getId()),
                r.getTo().getEntityName(),
                prepare(r.getTo().getId()),
                r.getFromRole(),
                r.getToRole(),
                r.getRelationName());
        Object relation = driver.execute(from(getRelation));

        if (relation == null) {
            String relationCreation = format("match $from isa %s has stix_id %s; $to isa %s has stix_id %s; insert (%s: $from, %s: $to) isa %s;",
                    r.getFrom().getEntityName(),
                    prepare(r.getFrom().getId()),
                    r.getTo().getEntityName(),
                    prepare(r.getTo().getId()),
                    r.getFromRole(),
                    r.getToRole(),
                    r.getRelationName());
            driver.execute(from(relationCreation));
        }
    }

    public static String prepare(String s) {
        return s != null ? "\"" + s.replace("\\", "\\\\").replaceAll("\"", "\\\\\"") + "\"" : null;
    }
}
