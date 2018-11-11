package org.opencti.model;

import org.opencti.model.database.GraknRelation;
import org.opencti.model.database.LoaderDriver;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

public interface StixElement {
    String getId();

    default void neo4j(LoaderDriver driver, Map<String, StixBase> stixElements) {
        //Do nothing
    }

    default void grakn(LoaderDriver driver, Map<String, StixBase> stixElements) {
        //Do nothing
    }

    default List<GraknRelation> extraRelations(Map<String, StixElement> stixElements) {
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
}
