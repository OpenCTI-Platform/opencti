package io.filigran.opencti.entities;

import io.filigran.opencti.OpenCTIApiClient;
import lombok.extern.slf4j.Slf4j;
import java.util.Map;

@Slf4j
public class StixCoreObject extends BaseEntity {
    private static final String PROPERTIES = """
            id standard_id entity_type parent_types spec_version created_at updated_at
            createdBy { ... on Identity { id standard_id entity_type name } }
            objectMarking { id standard_id definition_type definition x_opencti_order x_opencti_color }
            objectLabel { id value color }
            ... on AttackPattern { name description }
            ... on Campaign { name description }
            ... on CourseOfAction { name description }
            ... on Incident { name description }
            ... on Indicator { name pattern pattern_type }
            ... on Infrastructure { name description }
            ... on IntrusionSet { name description }
            ... on Malware { name description is_family }
            ... on ThreatActor { name description }
            ... on Tool { name description }
            ... on Vulnerability { name description }
            ... on Report { name description published }
            ... on Note { content }
            ... on Grouping { name description context }
            ... on StixCyberObservable { observable_value }
            """;

    public StixCoreObject(OpenCTIApiClient client) { super(client); }
    @Override protected String getEntityType() { return "StixCoreObject"; }
    @Override protected String getEntityName() { return "stixCoreObject"; }
    @Override protected String getEntityNamePlural() { return "stixCoreObjects"; }
    @Override protected String getProperties() { return PROPERTIES; }
    @Override protected String getOrderingEnum() { return "StixCoreObjectsOrdering"; }
}

