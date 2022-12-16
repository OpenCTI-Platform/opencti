import { UserInputError } from "apollo-server-express";
import {
  optionalizePredicate, 
  parameterizePredicate, 
  buildSelectVariables, 
  generateId, 
  OSCAL_NS,
  CyioError
} from "../../../utils.js";
import {
  oscalPartyReducer,
} from "../../oscal-common/resolvers/sparql-query.js";
import {
  componentReducer,
} from "../../component/resolvers/sparql-query.js";
import {
  selectObjectIriByIdQuery,
} from "../../../global/global-utils.js";


// Utility functions
export function getReducer( type ) {
  switch( type ) {
    case 'ACTOR':
      return actorReducer;
    case 'ACTIVITY':
      return activityReducer;
    case 'TOOL':
      return componentReducer;
    case 'ASSESSMENT-ASSET':
      return assessmentAssetReducer;
    case 'ASSESSMENT-PLATFORM':
      return assessmentPlatformReducer;
    case 'ASSESSMENT-SUBJECT':
      return assessmentSubjectReducer;
    case 'ASSOCIATED-ACTIVITY':
      return associatedActivityReducer;
    case 'CHARACTERIZATION':
      return characterizationReducer;
    case 'EVIDENCE':
      return evidenceReducer;
    case 'FACET':
      return facetReducer;
    case 'LOG-ENTRY-AUTHOR':
      return logEntryAuthorReducer;
    case 'MITIGATING-FACTOR':
      return mitigatingFactorReducer;
    case 'OBSERVATION':
      return observationReducer;
    case 'ORIGIN':
      return originReducer;
    case 'PARTY':
      return oscalPartyReducer;
    case 'REQUIRED-ASSET':
      return requiredAssetReducer;
    case 'RISK':
      return riskReducer;
    case 'RISK-LOG-ENTRY':
      return riskLogReducer;
    case 'RISK-RESPONSE':
      return riskResponseReducer;
    case 'SUBJECT':
      return subjectReducer;
    case 'TASK':
      return taskReducer;
    case 'VULNERABILITY-FACET':
      return vulnerabilityFacetReducer;
    default:
      throw new Error(`Unsupported reducer type ' ${type}'`)
  }
}

// TODO: Update to use objectMap capability
//       replace with selectObjectIriByIdQuery
export const getSubjectIriByIdQuery = (id, subjectType) => {
  let objType;
  switch(subjectType) {
    case 'assessment-platform':
      objType = 'AssessmentPlatform';
      break;
    case 'component':
    case 'tool':
      objType = 'Component';
      break;
    case 'inventory-item':
      objType = 'InventoryItem';
      break
    case 'location':
      objType = 'Location';
      break;
    case 'party':
      objType = 'Party';
      break;
    case 'user':
      objType = 'SystemUser'
      break;
    case 'resource':
      objType = 'Resource';
      break;
    default:
      objType = type;
      break;
  }


  return `
  SELECT DISTINCT ?iri 
  FROM <tag:stardog:api:context:local>
  WHERE {
      ?iri a <http://csrc.nist.gov/ns/oscal/common#${objType}> .
      ?iri <http://darklight.ai/ns/common#id> "${id}" .
  }
  `
}

// Reducers
const activityReducer = (item) => {
  // if no object type was returned, compute the type from the IRI
  if ( item.object_type === undefined ) {
    item.object_type = 'oscal-activity';
  }

  return {
    iri: item.iri,
    id: item.id,
    standard_id: item.id,
    ...(item.object_type && {entity_type: item.object_type}),
    ...(item.created && {created: item.created}),
    ...(item.modified && {modified: item.modified}),
    ...(item.labels && {labels_iri: item.labels}),
    ...(item.props && {props: item.props}),
    ...(item.links && {links_iri: item.links}),
    ...(item.remarks && {remarks_iri: item.remarks}),
    ...(item.relationships && {relationships_iri: item.relationships}),
    ...(item.name && {name: item.name} ),
    ...(item.description && {description: item.description}),
    ...(item.methods && {methods: item.methods}),
    ...(item.steps && {steps_iri: item.steps}),
    ...(item.related_controls && {related_controls_iri: item.related_controls}),
    ...(item.responsible_roles && { responsible_roles_iri: item.responsible_roles}),
  }
}
const actorReducer = (item) => {
  // if no object type was returned, compute the type from the IRI
  if ( item.object_type === undefined ) {
    item.object_type = 'actor';
  }

  return {
    iri: item.iri,
    id: item.id,
    standard_id: item.id,
    ...(item.object_type && {entity_type: item.object_type}),
    ...(item.props && {props: item.props}),
    ...(item.links && {links_iri: item.links}),
    ...(item.actor_type && {actor_type: item.actor_type} ),
    ...(item.actor_ref && {actor_ref_iri: item.actor_ref}),
    ...(item.role_ref && {role_ref_iri: item.role_ref}),
  }
}
const assessmentAssetReducer = (item) => {
  // if no object type was returned, compute the type from the IRI
  if ( item.object_type === undefined ) {
    item.object_type = 'assessment-asset';
  }
  return {
    iri: item.iri,
    id: item.id,
    standard_id: item.id,
    ...(item.object_type && {entity_type: item.object_type}),
    ...(item.components && {components_iri: item.components}),
    ...(item.assessment_platforms && {assessment_platforms_iri: item.assessment_platforms}),
  }
}
const assessmentPlatformReducer = (item) => {
  // if no object type was returned, compute the type from the IRI
  if ( item.object_type === undefined ) {
    item.object_type = 'assessment-platform';
  }

  return {
    iri: item.iri,
    id: item.id,
    standard_id: item.id,
    ...(item.object_type && {entity_type: item.object_type}),
    ...(item.created && {created: item.created}),
    ...(item.modified && {modified: item.modified}),
    ...(item.props && {props: item.props}),
    ...(item.links && {links_iri: item.links}),
    ...(item.remarks && {remarks_iri: item.remarks}),
    ...(item.name && {name: item.name}),
    ...(item.description && {description: item.description}),
    ...(item.uses_components && {uses_components_iri: item.uses_components}),
  }
}
const assessmentSubjectReducer = (item) => {
  // if no object type was returned, compute the type from the IRI
  if ( item.object_type === undefined ) {
    item.object_type = 'assessment-subject';
  }

  return {
    iri: item.iri,
    id: item.id,
    standard_id: item.id,
    ...(item.object_type && {entity_type: item.object_type}),
    ...(item.props && {props: item.props}),
    ...(item.links && {links_iri: item.links}),
    ...(item.remarks && {remarks_iri: item.remarks}),
    ...(item.subject_type && {subject_type: item.subject_type}),
    ...(item.description && {description: item.description}),
    ...(item.include_all !== undefined && {include_all: item.include_all}),
    ...(item.include_subjects && {include_subjects_iri: item.include_subjects}),
    ...(item.exclude_subjects && {exclude_subjects_iri: item.exclude_subjects}),
  }
}
const associatedActivityReducer = (item) => {
  // if no object type was returned, compute the type from the IRI
  if ( item.object_type === undefined ) {
    item.object_type = 'associated-activity';
  }

  return {
    iri: item.iri,
    id: item.id,
    standard_id: item.id,
    ...(item.object_type && {entity_type: item.object_type}),
    ...(item.props && {props: item.props}),
    ...(item.links && {links_iri: item.links}),
    ...(item.remarks && {remarks_iri: item.remarks}),
    ...(item.activity_id && {activity_id_iri: item.activity_id} ),
    ...(item.responsible_roles && { responsible_roles_iri: item.responsible_roles}),
    ...(item.subjects && {subjects_iri: item.subjects} ),
  }
}
const characterizationReducer = (item) => {
  // if no object type was returned, compute the type from the IRI
  if ( item.object_type === undefined ) {
    item.object_type = 'characterization';
  }

  return {
    iri: item.iri,
    id: item.id,
    standard_id: item.id,
    ...(item.object_type && {entity_type: item.object_type}),
    ...(item.created && {created: item.created}),
    ...(item.modified && {modified: item.modified}),
    ...(item.props && {props: item.props}),
    ...(item.links && {links_iri: item.links}),
    ...(item.remarks && {remarks_iri: item.remarks}),
    ...(item.origins && {origins_iri: item.origins}),
    ...(item.facets && {facets_iri: item.facets}),
  }
}
const evidenceReducer = (item) => {
  // if no object type was returned, compute the type from the IRI
  if ( item.object_type === undefined ) {
    item.object_type = 'evidence';
  }

  return {
    iri: item.iri,
    id: item.id,
    standard_id: item.id,
    ...(item.object_type && {entity_type: item.object_type}),
    ...(item.created && {created: item.created}),
    ...(item.modified && {modified: item.modified}),
    ...(item.props && {props: item.props}),
    ...(item.links && {links_iri: item.links}),
    ...(item.remarks && {remarks_iri: item.remarks}),
    ...(item.href && {href: item.href}),
    ...(item.description && {description: item.description}),
  }
}
const facetReducer = (item) => {
  // if no object type was returned, compute the type from the IRI
  if ( item.object_type === undefined ) {
    item.object_type = 'facet';
  }

  return {
    iri: item.iri,
    id: item.id,
    standard_id: item.id,
    ...(item.object_type && {entity_type: item.object_type}),
    ...(item.props && {props: item.props}),
    ...(item.links && {links_iri: item.links}),
    ...(item.remarks && {remarks_iri: item.remarks}),
    ...(item.risk_state && {risk_state: item.risk_state}),
    ...(item.source_system && {source_system: item.source_system}),
    ...(item.facet_name && {facet_name: item.facet_name}),
    ...(item.facet_value && {facet_value: item.facet_value}),
  }
}
const logEntryAuthorReducer = (item) => {
  // if no object type was returned, compute the type from the IRI
  if ( item.object_type === undefined ) {
    item.object_type = 'log-entry-author';
  }

  return {
    iri: item.iri,
    id: item.id,
    standard_id: item.id,
    ...(item.object_type && {entity_type: item.object_type}),
    ...(item.party && {party_iri: item.party}),
    ...(item.role && {role_id: item.role}),
  }
}
const mitigatingFactorReducer = (item) => {
  // if no object type was returned, compute the type from the IRI
  if ( item.object_type === undefined ) {
    item.object_type = 'mitigation-factor';
  }

  return {
    iri: item.iri,
    id: item.id,
    standard_id: item.id,
    ...(item.object_type && {entity_type: item.object_type}),
    ...(item.created && {created: item.created}),
    ...(item.modified && {modified: item.modified}),
    ...(item.labels && {labels_iri: item.labels}),
    ...(item.props && {props: item.props}),
    ...(item.links && {links_iri: item.links}),
    ...(item.remarks && {remarks_iri: item.remarks}),
    ...(item.relationships && {relationships_iri: item.relationships}),
    ...(item.description && {description: item.description}),
    ...(item.subjects && {subjects_iri: item.subjects}),
  }
}
const observationReducer = (item) => {
  // if no object type was returned, compute the type from the IRI
  if ( item.object_type === undefined ) {
    item.object_type = 'observation';
  }
  // work around issue in data
  if (item.methods !== undefined) {
    const uppercased = item.methods.map(name => name.toUpperCase());
    item.methods = uppercased;
  }

  return {
    iri: item.iri,
    id: item.id,
    standard_id: item.id,
    ...(item.object_type && {entity_type: item.object_type}),
    ...(item.created && {created: item.created}),
    ...(item.modified && {modified: item.modified}),
    ...(item.labels && {labels_iri: item.labels}),
    ...(item.props && {props: item.props}),
    ...(item.links && {links_iri: item.links}),
    ...(item.remarks && {remarks_iri: item.remarks}),
    ...(item.relationships && {relationships_iri: item.relationships}),
    ...(item.name && {name: item.name}),
    ...(item.description && {description: item.description}),
    ...(item.methods && {methods: item.methods }),
    ...(item.observation_types && {observation_types: item.observation_types} ),
    ...(item.origins && {origins_iri: item.origins}),
    ...(item.subjects && {subjects_iri: item.subjects}),
    ...(item.relevant_evidence && {relevant_evidence_iri: item.relevant_evidence}),
    ...(item.collected && {collected: item.collected}),
    ...(item.expires && {expires: item.expires}),
  }    
}
const originReducer = (item) => {
  // if no object type was returned, compute the type from the IRI
  if ( item.object_type === undefined ) {
    item.object_type = 'origin';
  }

  return {
    iri: item.iri,
    id: item.id,
    standard_id: item.id,
    ...(item.object_type && {entity_type: item.object_type}),
    ...(item.props && {props: item.props}),
    ...(item.links && {links_iri: item.links}),
    ...(item.origin_actors && {origin_actors_iri: item.origin_actors}),
    ...(item.related_tasks && {related_tasks_iri: item.related_tasks}),
  }

}
const requiredAssetReducer = (item) => {
  // if no object type was returned, compute the type from the IRI
  if ( item.object_type === undefined ) {
    item.object_type = 'required-asset';
  }

  return {
    iri: item.iri,
    id: item.id,
    standard_id: item.id,
    ...(item.object_type && {entity_type: item.object_type}),
    ...(item.props && {props: item.props}),
    ...(item.links && {links_iri: item.links}),
    ...(item.remarks && {remarks_iri: item.remarks}),
    ...(item.subjects && {subjects_iri: item.subjects}),
    ...(item.name && {name: item.name}),
    ...(item.description && {description: item.description}),
  }
}
const riskReducer = (item) => {
  // if no object type was returned, compute the type from the IRI
  if ( item.object_type === undefined ) {
    item.object_type = 'risk';
  }
  
  if (!('deadline' in item)) item.deadline = null;
  if ( !('false_positive' in item)) item.false_positive = false;
  if ( !('accepted' in item)) item.accepted = false;
  if ( !('risk_adjusted' in item)) item.risk_adjusted = false;
  if ( !('vendor_dependency' in item)) item.vendor_dependency = false;

  return {
    iri: item.iri,
    id: item.id,
    standard_id: item.id,
    ...(item.object_type && {entity_type: item.object_type}),
    ...(item.created && {created: item.created}),
    ...(item.modified && {modified: item.modified}),
    ...(item.labels && {labels_iri: item.labels}),
    ...(item.props && {props: item.props}),
    ...(item.links && {links_iri: item.links}),
    ...(item.remarks && {remarks_iri: item.remarks}),
    ...(item.relationships && {relationships_iri: item.relationships}),
    ...(item.name && {name: item.name} ),
    ...(item.description && {description: item.description}),
    ...(item.statement && {statement: item.statement}),
    ...(item.risk_status && {risk_status: item.risk_status}),
    ...(item.risk_level && {risk_level: item.risk_level}),
    ...(item.origins && {origins_iri: item.origins}),
    ...(item.threats && {threats_iri: item.threats}),
    ...(item.characterizations && {characterizations_iri: item.characterizations}),
    ...(item.mitigating_factors && {mitigating_factors_iri: item.mitigating_factors}),
    ...(item.first_seen && {first_seen: item.first_seen}),
    ...(item.last_seen && {last_seen: item.last_seen}),
    ...(item.deadline && {deadline: item.deadline}),
    ...(item.remediations && {remediations_iri: item.remediations}),
    ...(item.risk_log && {risk_log_iri: item.risk_log}),
    ...(item.related_observations && {related_observations_iri: item.related_observations}),
    ...(item.related_observation_ids && {related_observation_ids: item.related_observation_ids}),
    ...(item.false_positive !== undefined && {false_positive: item.false_positive}),
    ...(item.accepted !== undefined && {accepted: item.accepted}),
    ...(item.risk_adjusted !== undefined && {risk_adjusted: item.risk_adjusted}),
    ...(item.priority && {priority: item.priority}),
    ...(item.vendor_dependency !== undefined && {vendor_dependency: item.vendor_dependency}),
    ...(item.impacted_control_id && {impacted_control_iri: item.impacted_control_id}),
    ...(item.response_type && {response_type: item.response_type}),
    ...(item.lifecycle && {lifecycle: item.lifecycle}),
    ...(item.poam_id && {poam_id: item.poam_id}),
    ...(item.occurrences && {occurrences: item.occurrences}),
  }
}
const riskLogReducer = (item) => {
  // if no object type was returned, compute the type from the IRI
  if ( item.object_type === undefined ) {
    item.object_type = 'risk-log-entry';
  }

  return {
    iri: item.iri,
    id: item.id,
    standard_id: item.id,
    ...(item.object_type && {entity_type: item.object_type}),
    ...(item.created && {created: item.created}),
    ...(item.modified && {modified: item.modified}),
    ...(item.labels && {labels_iri: item.labels}),
    ...(item.props && {props: item.props}),
    ...(item.links && {links_iri: item.links}),
    ...(item.remarks && {remarks_iri: item.remarks}),
    ...(item.relationships && {relationships_iri: item.relationships}),
    ...(item.entry_type && {entry_type: item.entry_type}),
    ...(item.name && {name: item.name} ),
    ...(item.description && {description: item.description}),
    ...(item.event_start && {event_start: item.event_start}),
    ...(item.event_end && {event_end: item.event_end}),
    ...(item.logged_by && {logged_by_iri: item.logged_by}),
    ...(item.status_change && {status_change: item.status_change}),
    ...(item.related_responses && {related_responses_iri: item.related_responses}),
  }
}
const riskResponseReducer = (item) => {
  // if no object type was returned, compute the type from the IRI
  if ( item.object_type === undefined ) {
    item.object_type = 'risk-response';
  }

  return {
    iri: item.iri,
    id: item.id,
    standard_id: item.id,
    ...(item.object_type && {entity_type: item.object_type}),
    ...(item.created && {created: item.created}),
    ...(item.modified && {modified: item.modified}),
    ...(item.labels && {labels_iri: item.labels}),
    ...(item.props && {props: item.props}),
    ...(item.links && {links_iri: item.links}),
    ...(item.remarks && {remarks_iri: item.remarks}),
    ...(item.relationships && {relationships_iri: item.relationships}),
    ...(item.name && {name: item.name} ),
    ...(item.description && {description: item.description}),
    ...(item.response_type && {response_type: item.response_type}),
    ...(item.lifecycle && {lifecycle: item.lifecycle}),
    ...(item.origins && {origins_iri: item.origins}),
    ...(item.required_assets && {required_assets_iri: item.required_assets}),
    ...(item.tasks && {tasks_iri: item.tasks}),
  }
}
const subjectReducer = (item) => {
  // if no object type was returned, compute the type from the IRI
  if ( item.object_type === undefined ) {
    item.object_type = 'subject';
  }

  // TODO: WORKAROUND - remove bad data
  if (item.name !== undefined && item.name === 'undefined') {
    item.name = undefined
  }
  // END WORKAROUND

  // populate name if we have the actual subject's information
  if (item.name === undefined && (item.subject_name !== undefined)) {
    item.name = item.subject_name;
    if (item.subject_version !== undefined) item.name = item.name + ` ${item.subject_version}`;
  }
  return {
    iri: item.iri,
    id: item.id,
    standard_id: item.id,
    ...(item.object_type && {entity_type: item.object_type}),
    ...(item.props && {props: item.props}),
    ...(item.links && {links_iri: item.links}),
    ...(item.remarks && {remarks_iri: item.remarks}),
    ...(item.name && {name: item.name}),
    ...(item.subject_type && {subject_type: item.subject_type}),
    ...(item.subject_ref && {subject_ref_iri: item.subject_ref}),
    ...(item.subject_context && {subject_context: item.subject_context}),
    ...(item.subject_id && {subject_id: item.subject_id}),
    ...(item.subject_name && {subject_name: item.subject_name}),
    ...(item.subject_version && {subject_version: item.subject_version}),
    ...(item.subject_asset_type && {subject_asset_type: item.subject_asset_type}),
    ...(item.subject_component_type && {subject_component_type: item.subject_component_type}),
    ...(item.subject_party_type && {subject_party_type: item.subject_party_type}),
    ...(item.subject_location_type && {subject_location_type: item.subject_location_type}),
    ...(item.subject_user_type && {subject_user_type: item.subject_user_type}),
  }
}
const taskReducer = (item) => {
  // if no object type was returned, compute the type from the IRI
  if ( item.object_type === undefined ) {
    item.object_type = 'oscal-task';
  }

  return {
    iri: item.iri,
    id: item.id,
    standard_id: item.id,
    ...(item.object_type && {entity_type: item.object_type}),
    ...(item.created && {created: item.created}),
    ...(item.modified && {modified: item.modified}),
    ...(item.labels && {labels_iri: item.labels}),
    ...(item.props && {props: item.props}),
    ...(item.links && {links_iri: item.links}),
    ...(item.remarks && {remarks_iri: item.remarks}),
    ...(item.relationships && {relationships_iri: item.relationships}),
    ...(item.task_type && {task_type: item.task_type}),
    ...(item.name && {name: item.name}),
    ...(item.description && {description: item.description}),
    // ...(item.timing && {timing_iri: item.timing}),
    ...(item.on_date && {on_date: item.on_date}),
    ...(item.start_date && {start_date: item.start_date}),
    ...(item.end_date && {end_date: item.end_date}),
    ...(item.frequency_period && {frequency_period: item.frequency_period}),
    ...(item.time_unit && {time_unit: item.time_unit}),
    ...(item.related_tasks && {related_tasks_iri: item.related_tasks}),
    ...(item.task_dependencies && {task_dependencies_iri: item.task_dependencies}),
    ...(item.associated_activities && {associated_activities_iri: item.associated_activities}),
    ...(item.subjects && {subjects_iri: item.subjects}),
    ...(item.responsible_roles && {responsible_roles_iri: item.responsible_roles}),
  }
}
const vulnerabilityFacetReducer = (item) => {
  // if no object type was returned, compute the type from the IRI
  if ( item.object_type === undefined ) {
    item.object_type = 'vulnerability-facet';
  }

  return {
    iri: item.iri,
    id: item.id,
    standard_id: item.id,
    ...(item.object_type && {entity_type: item.object_type}),
    ...(item.links && {links_iri: item.links}),
    ...(item.remarks && {remarks_iri: item.remarks}),
    ...(item.risk_state && {risk_state: item.risk_state}),
    ...(item.source_system && {source_system: item.source_system}),
    ...(item.vulnerability_id && {vulnerability_id: item.vulnerability_id}),
    ...(item.cvss20_vector_string && {cvss20_vector_string: item.cvss20_vector_string}),
    ...(item.cvss20_base_score != undefined && {cvss20_base_score: item.cvss20_base_score}),
    ...(item.cvss20_temporal_score != undefined && {cvss20_temporal_score: item.cvss20_temporal_score}),
    ...(item.cvss20_environmental_score != undefined && {cvss20_environmental_score: item.cvss20_environmental_score}),
    ...(item.cvss30_vector_string && {cvss30_vector_string: item.cvss30_vector_string}),
    ...(item.cvss30_base_score != undefined && {cvss30_base_score: item.cvss30_base_score}),
    ...(item.cvss30_temporal_score != undefined && {cvss30_temporal_score: item.cvss30_temporal_score}),
    ...(item.cvss30_environmental_score != undefined && {cvss30_environmental_score: item.cvss30_environmental_score}),
    ...(item.score_rationale && {score_rationale: item.score_rationale}),
    ...(item.exploitability && {exploitability: item.exploitability}),
    ...(item.exploit_available && {exploit_available: item.exploit_available}),
  }
}



// Activity support functions
export const insertActivityQuery = (propValues) => {
  const id_material = {
    ...(propValues.name && {"name": propValues.name}),
    ...(propValues.methods && {"methods": propValues.methods}),
  } ;
  const id = generateId( id_material, OSCAL_NS );
  const timestamp = new Date().toISOString();

  // escape any special characters (e.g., newline)
  if (propValues.description !== undefined) {
    if (propValues.description.includes('\n')) propValues.description = propValues.description.replace(/\n/g, '\\n');
    if (propValues.description.includes('\"')) propValues.description = propValues.description.replace(/\"/g, '\\"');
    if (propValues.description.includes("\'")) propValues.description = propValues.description.replace(/\'/g, "\\'");
  }

  const iri = `<http://csrc.nist.gov/ns/oscal/assessment/common#Activity-${id}>`;
  const insertPredicates = Object.entries(propValues)
      .filter((propPair) => activityPredicateMap.hasOwnProperty(propPair[0]))
      .map((propPair) => activityPredicateMap[propPair[0]].binding(iri, propPair[1]))
      .join('. \n      ');
  const query = `
  INSERT DATA {
    GRAPH ${iri} {
      ${iri} a <http://csrc.nist.gov/ns/oscal/assessment/common#Activity> .
      ${iri} a <http://csrc.nist.gov/ns/oscal/common#Object> .
      ${iri} a <http://darklight.ai/ns/common#Object> .
      ${iri} <http://darklight.ai/ns/common#id> "${id}" .
      ${iri} <http://darklight.ai/ns/common#object_type> "oscal-activity" . 
      ${iri} <http://darklight.ai/ns/common#created> "${timestamp}"^^xsd:dateTime . 
      ${iri} <http://darklight.ai/ns/common#modified> "${timestamp}"^^xsd:dateTime . 
      ${insertPredicates}
    }
  }
  `;
  return {iri, id, query}  
}
export const selectActivityQuery = (id, select) => {
  return selectActivityByIriQuery(`http://csrc.nist.gov/ns/oscal/assessment/common#Activity-${id}`, select);
}
export const selectActivityByIriQuery = (iri, select) => {
  if (!iri.startsWith('<')) iri = `<${iri}>`;
  if (select === undefined || select === null) select = Object.keys(activityPredicateMap);
  
  const { selectionClause, predicates } = buildSelectVariables(activityPredicateMap, select);
  return `
  SELECT ?iri ${selectionClause}
  FROM <tag:stardog:api:context:local>
  WHERE {
    BIND(${iri} AS ?iri)
    ?iri a <http://csrc.nist.gov/ns/oscal/assessment/common#Activity> .
    ${predicates}
  }
  `
}
export const selectAllActivities = (select, args) => {
  if (select === undefined || select === null) select = Object.keys(activityPredicateMap);
  if (!select.includes('id')) select.push('id');

  if (args !== undefined ) {
    if ( args.filters !== undefined ) {
      for( const filter of args.filters) {
        if (!select.includes(filter.key)) select.push( filter.key );
      }
    }
    
    // add value of orderedBy's key to cause special predicates to be included
    if ( args.orderedBy !== undefined ) {
      if (!select.includes(args.orderedBy)) select.push(args.orderedBy);
    }
  }

  const { selectionClause, predicates } = buildSelectVariables(activityPredicateMap, select);
  return `
  SELECT DISTINCT ?iri ${selectionClause} 
  FROM <tag:stardog:api:context:local>
  WHERE {
    ?iri a <http://csrc.nist.gov/ns/oscal/assessment/common#Activity> . 
    ${predicates}
  }
  `
}
export const deleteActivityQuery = (id) => {
  const iri = `http://csrc.nist.gov/ns/oscal/assessment/common#Activity-${id}`;
  return deleteActivityByIriQuery(iri);
}
export const deleteActivityByIriQuery = (iri) => {
  return `
  DELETE {
    GRAPH <${iri}> {
      ?iri ?p ?o
    }
  } WHERE {
    GRAPH <${iri}> {
      ?iri a <http://csrc.nist.gov/ns/oscal/assessment/common#Activity> .
      ?iri ?p ?o
    }
  }
  `
}
export const attachToActivityQuery = (id, field, itemIris) => {
  const iri = `<http://csrc.nist.gov/ns/oscal/assessment/common#Activity-${id}>`;
  if (!activityPredicateMap.hasOwnProperty(field)) return null;
  const predicate = activityPredicateMap[field].predicate;
  let statements;
  if (Array.isArray(itemIris)) {
    statements = itemIris
      .map((itemIri) => `${iri} ${predicate} ${itemIri}`)
      .join(".\n        ")
    }
  else {
    if (!itemIris.startsWith('<')) itemIris = `<${itemIris}>`;
    statements = `${iri} ${predicate} ${itemIris}`;
  }
  return `
  INSERT DATA {
    GRAPH ${iri} {
      ${statements}
    }
  }
  `
}
export const detachFromActivityQuery = (id, field, itemIris) => {
  const iri = `<http://csrc.nist.gov/ns/oscal/assessment/common#Activity-${id}>`;
  if (!activityPredicateMap.hasOwnProperty(field)) return null;
  const predicate = activityPredicateMap[field].predicate;
  let statements;
  if (Array.isArray(itemIris)) {
    statements = itemIris
      .map((itemIri) => `${iri} ${predicate} ${itemIri}`)
      .join(".\n        ")
    }
  else {
    if (!itemIris.startsWith('<')) itemIris = `<${itemIris}>`;
    statements = `${iri} ${predicate} ${itemIris}`;
  }
  return `
  DELETE DATA {
    GRAPH ${iri} {
      ${statements}
    }
  }
  `
}

// Actor support functions
export const insertActorQuery = (propValues) => {
  const id_material = {
    ...(propValues.actor_ref && {"actor_ref": propValues.actor_ref}),
    ...(propValues.actor_type && {"actor_type": propValues.actor_type}),
  } ;
  const id = generateId( id_material, OSCAL_NS );
  const iri = `<http://csrc.nist.gov/ns/oscal/assessment/common#Actor-${id}>`;
  const insertPredicates = Object.entries(propValues)
      .filter((propPair) => actorPredicateMap.hasOwnProperty(propPair[0]))
      .map((propPair) => actorPredicateMap[propPair[0]].binding(iri, propPair[1]))
      .join('. \n      ');
  const query = `
  INSERT DATA {
    GRAPH ${iri} {
      ${iri} a <http://csrc.nist.gov/ns/oscal/assessment/common#Actor> .
      ${iri} a <http://csrc.nist.gov/ns/oscal/common#ComplexDatatype> .
      ${iri} a <http://darklight.ai/ns/common#ComplexDatatype> .
      ${iri} <http://darklight.ai/ns/common#id> "${id}" .
      ${iri} <http://darklight.ai/ns/common#object_type> "actor" . 
      ${insertPredicates}
    }
  }
  `;
  return {iri, id, query}  
}
export const insertActorsQuery = (actors) => {
  const graphs = [], actorIris = [];
  actors.forEach((actor) => {
    const id_material = {
      ...(actor.actor_ref && {"actor_ref": actor.actor_ref}),
      ...(actor.actor_type && {"actor_type": actor.actor_type}),
    } ;
    const id = generateId( id_material, OSCAL_NS );
    const insertPredicates = [];
    const iri = `<http://csrc.nist.gov/ns/oscal/assessment/common#Actor-${id}>`;
    actorIris.push(iri);
    insertPredicates.push(`${iri} a <http://csrc.nist.gov/ns/oscal/assessment/common#Actor>`);
    insertPredicates.push(`${iri} a <http://csrc.nist.gov/ns/oscal/common#ComplexDatatype>`);
    insertPredicates.push(`${iri} a <http://darklight.ai/ns/common#ComplexDatatype>`);
    insertPredicates.push(`${iri} <http://darklight.ai/ns/common#id> "${id}"`);
    insertPredicates.push(`${iri} <http://darklight.ai/ns/common#object_type> "actor"`); 
    insertPredicates.push(`${iri} <http://csrc.nist.gov/ns/oscal/assessment/common#actor_type> "${actor.actor_type}"`);
    insertPredicates.push(`${iri} <http://csrc.nist.gov/ns/oscal/assessment/common#actor_ref> <${actor.actor_ref}>`);
    if (actor.role_ref !== undefined) {
      insertPredicates.push(`${iri} <http://csrc.nist.gov/ns/oscal/common#role> <${actor.role_ref}>`);
    }
    graphs.push(`
  GRAPH ${iri} {
    ${insertPredicates.join(".\n        ")}
  }
    `)
  })
  const query = `
  INSERT DATA {
    ${graphs.join("\n")}
  }`;
  return {actorIris, query};
}
export const selectActorQuery = (id, select) => {
  return selectActorByIriQuery(`http://csrc.nist.gov/ns/oscal/assessment/common#Actor-${id}`, select);
}
export const selectActorByIriQuery = (iri, select) => {
  if (!iri.startsWith('<')) iri = `<${iri}>`;
  if (select === undefined || select === null) select = Object.keys(actorPredicateMap);
  // this is needed to assist in the determination of the actor
  if (!select.includes('actor_type')) select.push('actor_type');
  const { selectionClause, predicates } = buildSelectVariables(actorPredicateMap, select);
  return `
  SELECT ?iri ${selectionClause}
  FROM <tag:stardog:api:context:local>
  WHERE {
    BIND(${iri} AS ?iri)
    ?iri a <http://csrc.nist.gov/ns/oscal/assessment/common#Actor> .
    ${predicates}
  }
  `
}
export const selectAllActors = (select, args) => {
  if (select === undefined || select === null) select = Object.keys(actorPredicateMap);
  if (!select.includes('id')) select.push('id');

  if (args !== undefined ) {
    if ( args.filters !== undefined ) {
      for( const filter of args.filters) {
        if (!select.includes(filter.key)) select.push( filter.key );
      }
    }
    
    // add value of orderedBy's key to cause special predicates to be included
    if ( args.orderedBy !== undefined ) {
      if (!select.includes(args.orderedBy)) select.push(args.orderedBy);
    }
  }

  const { selectionClause, predicates } = buildSelectVariables(actorPredicateMap, select);
  return `
  SELECT DISTINCT ?iri ${selectionClause} 
  FROM <tag:stardog:api:context:local>
  WHERE {
    ?iri a <http://csrc.nist.gov/ns/oscal/assessment/common#Actor> . 
    ${predicates}
  }
  `
}
export const deleteActorQuery = (id) => {
  const iri = `http://csrc.nist.gov/ns/oscal/assessment/common#Actor-${id}`;
  return deleteActorByIriQuery(iri);
}
export const deleteActorByIriQuery = (iri) => {
  return `
  DELETE {
    GRAPH <${iri}> {
      ?iri ?p ?o
    }
  } WHERE {
    GRAPH <${iri}> {
      ?iri a <http://csrc.nist.gov/ns/oscal/assessment/common#Actor> .
      ?iri ?p ?o
    }
  }
  `
}
export const attachToActorQuery = (id, field, itemIris) => {
  const iri = `<http://csrc.nist.gov/ns/oscal/assessment/common#Actor-${id}>`;
  if (!actorPredicateMap.hasOwnProperty(field)) return null;
  const predicate = actorPredicateMap[field].predicate;
  let statements;
  if (Array.isArray(itemIris)) {
    statements = itemIris
      .map((itemIri) => `${iri} ${predicate} ${itemIri}`)
      .join(".\n        ")
    }
  else {
    if (!itemIris.startsWith('<')) itemIris = `<${itemIris}>`;
    statements = `${iri} ${predicate} ${itemIris}`;
  }
  return `
  INSERT DATA {
    GRAPH ${iri} {
      ${statements}
    }
  }
  `
}
export const detachFromActorQuery = (id, field, itemIris) => {
  const iri = `<http://csrc.nist.gov/ns/oscal/assessment/common#Actor-${id}>`;
  if (!actorPredicateMap.hasOwnProperty(field)) return null;
  const predicate = actorPredicateMap[field].predicate;
  let statements;
  if (Array.isArray(itemIris)) {
    statements = itemIris
      .map((itemIri) => `${iri} ${predicate} ${itemIri}`)
      .join(".\n        ")
    }
  else {
    if (!itemIris.startsWith('<')) itemIris = `<${itemIris}>`;
    statements = `${iri} ${predicate} ${itemIris}`;
  }
  return `
  DELETE DATA {
    GRAPH ${iri} {
      ${statements}
    }
  }
  `
}

// AssessmentAsset support functions
export const insertAssessmentAssetQuery = (propValues) => {
  const id = propValues.id;
  const iri = `<http://csrc.nist.gov/ns/oscal/assessment/common#AssessmentAsset-${id}>`;
  const insertPredicates = Object.entries(propValues)
      .filter((propPair) => actorPredicateMap.hasOwnProperty(propPair[0]))
      .map((propPair) => actorPredicateMap[propPair[0]].binding(iri, propPair[1]))
      .join('. \n      ');
  const query = `
  INSERT DATA {
    GRAPH ${iri} {
      ${iri} a <http://csrc.nist.gov/ns/oscal/assessment/common#AssessmentAsset> .
      ${iri} a <http://csrc.nist.gov/ns/oscal/common#ComplexDatatype> .
      ${iri} a <http://darklight.ai/ns/common#ComplexDatatype> .
      ${iri} <http://darklight.ai/ns/common#id> "${id}" .
      ${iri} <http://darklight.ai/ns/common#object_type> "assessment-asset" . 
      ${insertPredicates}
    }
  }
  `;
  return {iri, id, query}  
}
export const selectAssessmentAssetQuery = (id, select) => {
  return selectAssessmentAssetByIriQuery(`http://csrc.nist.gov/ns/oscal/assessment/common#AssessmentAsset-${id}`, select);
}
export const selectAssessmentAssetByIriQuery = (iri, select) => {
  if (!iri.startsWith('<')) iri = `<${iri}>`;
  if (select === undefined || select === null) select = Object.keys(assessmentAssetPredicateMap);
  if (!select.includes('id')) select.push('id');
  const { selectionClause, predicates } = buildSelectVariables(assessmentAssetPredicateMap, select);
  return `
  SELECT ?iri ${selectionClause}
  FROM <tag:stardog:api:context:local>
  WHERE {
    BIND(${iri} AS ?iri)
    ?iri a <http://csrc.nist.gov/ns/oscal/assessment/common#AssessmentAsset> .
    ${predicates}
  }
  `
}
export const selectAllAssessmentAssets = (select, args, parent) => {
  let constraintClause = '';
  if (select === undefined || select === null) select = Object.keys(assessmentAssetPredicateMap);
  if (!select.includes('id')) select.push('id');

  if (args !== undefined ) {
    if ( args.filters !== undefined ) {
      for( const filter of args.filters) {
        if (!select.includes(filter.key)) select.push( filter.key );
      }
    }
    
    // add value of orderedBy's key to cause special predicates to be included
    if ( args.orderedBy !== undefined ) {
      if (!select.includes(args.orderedBy)) select.push(args.orderedBy);
    }
  }

  const { selectionClause, predicates } = buildSelectVariables(assessmentAssetPredicateMap, select);
  // add constraint clause to limit to those that are referenced by the specified POAM
  if (parent !== undefined && parent.iri !== undefined) {
    let classTypeIri, predicate;
    if (parent.entity_type === 'poam-local-definitions') {
      classTypeIri = '<http://csrc.nist.gov/ns/oscal/poam#LocalDefinition>';
      predicate = '<http://csrc.nist.gov/ns/oscal/assessment/common#assessment_assets>';
    }
    if (parent.entity_type === 'result-local-definitions') {
      classTypeIri = '<http://csrc.nist.gov/ns/oscal/assessment-results#LocalDefinition>';
      predicate = '<http://csrc.nist.gov/ns/oscal/assessment/common#assessment_assets>';
    }
    if (parent.entity_type === 'assessment-plan') {
      classTypeIri = '<http://csrc.nist.gov/ns/oscal/common#AssessmentPlan>';
      predicate = '<http://csrc.nist.gov/ns/oscal/assessment/common#assessment_assets>';
    }
    // define a constraint to limit retrieval to only those referenced by the parent
    constraintClause = `
    {
      SELECT DISTINCT ?iri
      WHERE {
          <${parent.iri}> a ${classTypeIri} ;
            ${predicate} ?iri .
      }
    }
    `;
  }
  return `
  SELECT DISTINCT ?iri ${selectionClause} 
  FROM <tag:stardog:api:context:local>
  WHERE {
    ?iri a <http://csrc.nist.gov/ns/oscal/assessment/common#AssessmentAsset> . 
    ${predicates}
    ${constraintClause}
  }
  `
}
export const deleteAssessmentAssetQuery = (id) => {
  const iri = `http://csrc.nist.gov/ns/oscal/assessment/common#AssessmentAsset-${id}`;
  return deleteAssessmentAssetByIriQuery(iri);
}
export const deleteAssessmentAssetByIriQuery = (iri) => {
  return `
  DELETE {
    GRAPH <${iri}> {
      ?iri ?p ?o
    }
  } WHERE {
    GRAPH <${iri}> {
      ?iri a <http://csrc.nist.gov/ns/oscal/assessment/common#AssessmentAsset> .
      ?iri ?p ?o
    }
  }
  `
}
export const attachToAssessmentAssetQuery = (id, field, itemIris) => {
  const iri = `<http://csrc.nist.gov/ns/oscal/assessment/common#AssessmentAsset-${id}>`;
  if (!assessmentAssetPredicateMap.hasOwnProperty(field)) return null;
  const predicate = assessmentAssetPredicateMap[field].predicate;
  let statements;
  if (Array.isArray(itemIris)) {
    statements = itemIris
      .map((itemIri) => `${iri} ${predicate} ${itemIri}`)
      .join(".\n        ")
    }
  else {
    if (!itemIris.startsWith('<')) itemIris = `<${itemIris}>`;
    statements = `${iri} ${predicate} ${itemIris}`;
  }
  return `
  INSERT DATA {
    GRAPH ${iri} {
      ${statements}
    }
  }
  `
}
export const detachFromAssessmentAssetQuery = (id, field, itemIris) => {
  const iri = `<http://csrc.nist.gov/ns/oscal/assessment/common#AssessmentAsset-${id}>`;
  if (!assessmentAssetPredicateMap.hasOwnProperty(field)) return null;
  const predicate = assessmentAssetPredicateMap[field].predicate;
  let statements;
  if (Array.isArray(itemIris)) {
    statements = itemIris
      .map((itemIri) => `${iri} ${predicate} ${itemIri}`)
      .join(".\n        ")
    }
  else {
    if (!itemIris.startsWith('<')) itemIris = `<${itemIris}>`;
    statements = `${iri} ${predicate} ${itemIris}`;
  }
  return `
  DELETE DATA {
    GRAPH ${iri} {
      ${statements}
    }
  }
  `  
}

// AssessmentPlatform support functions
export const insertAssessmentPlatformQuery = (propValues) => {
  let id;
  if (propValues.name === 'Tenable') {
    id = '57853743-fc7d-5967-a1b6-f09a4fc73b15';
  } else if (propValues.name == 'Rapid7') {
    id = '828a147d-92ac-5f4a-acc6-b71966d6962c';
  } else {
    const id_material = {
      ...(propValues.name && {"name": propValues.name}),
    } ;
    id = generateId( id_material, OSCAL_NS );  
  }
  const timestamp = new Date().toISOString();

  // escape any special characters (e.g., newline)
  if (propValues.description !== undefined) {
    if (propValues.description.includes('\n')) propValues.description = propValues.description.replace(/\n/g, '\\n');
    if (propValues.description.includes('\"')) propValues.description = propValues.description.replace(/\"/g, '\\"');
    if (propValues.description.includes("\'")) propValues.description = propValues.description.replace(/\'/g, "\\'");
  }

  const iri = `<http://csrc.nist.gov/ns/oscal/assessment/common#AssessmentPlatform-${id}>`;
  const insertPredicates = Object.entries(propValues)
      .filter((propPair) => assessmentPlatformPredicateMap.hasOwnProperty(propPair[0]))
      .map((propPair) => assessmentPlatformPredicateMap[propPair[0]].binding(iri, propPair[1]))
      .join('. \n      ');
  const query = `
  INSERT DATA {
    GRAPH ${iri} {
      ${iri} a <http://csrc.nist.gov/ns/oscal/assessment/common#AssessmentPlatform> .
      ${iri} a <http://csrc.nist.gov/ns/oscal/common#Object> .
      ${iri} a <http://darklight.ai/ns/common#Object> .
      ${iri} <http://darklight.ai/ns/common#id> "${id}" .
      ${iri} <http://darklight.ai/ns/common#object_type> "assessment-platform" . 
      ${iri} <http://darklight.ai/ns/common#created> "${timestamp}"^^xsd:dateTime . 
      ${iri} <http://darklight.ai/ns/common#modified> "${timestamp}"^^xsd:dateTime . 
      ${insertPredicates}
    }
  }
  `;
  return {iri, id, query}  
}
export const selectAssessmentPlatformQuery = (id, select) => {
  return selectAssessmentPlatformByIriQuery(`http://csrc.nist.gov/ns/oscal/assessment/common#AssessmentPlatform-${id}`, select);
}
export const selectAssessmentPlatformByIriQuery = (iri, select) => {
  if (!iri.startsWith('<')) iri = `<${iri}>`;
  if (select === undefined || select === null) select = Object.keys(assessmentPlatformPredicateMap);
  if (!select.includes('id')) select.push('id');
  const { selectionClause, predicates } = buildSelectVariables(assessmentPlatformPredicateMap, select);
  return `
  SELECT ?iri ${selectionClause}
  FROM <tag:stardog:api:context:local>
  WHERE {
    BIND(${iri} AS ?iri)
    ?iri a <http://csrc.nist.gov/ns/oscal/assessment/common#AssessmentPlatform> .
    ${predicates}
  }
  `
}
export const selectAllAssessmentPlatforms = (select, args, parent) => {
  let constraintClause = '';
  if (select === undefined || select === null) select = Object.keys(assessmentPlatformPredicateMap);
  if (!select.includes('id')) select.push('id');

  if (args !== undefined ) {
    if ( args.filters !== undefined ) {
      for( const filter of args.filters) {
        if (!select.includes(filter.key)) select.push( filter.key );
      }
    }
    
    // add value of orderedBy's key to cause special predicates to be included
    if ( args.orderedBy !== undefined ) {
      if (!select.includes(args.orderedBy)) select.push(args.orderedBy);
    }
  }

  const { selectionClause, predicates } = buildSelectVariables(assessmentPlatformPredicateMap, select);
  // add constraint clause to limit to those that are referenced by the specified POAM
  if (parent !== undefined && parent.iri !== undefined) {
    let classTypeIri, predicate;
    if (parent.entity_type === 'assessment-asset') {
      classTypeIri = '<http://csrc.nist.gov/ns/oscal/assessment/common#AssessmentAsset>';
      predicate = '<http://csrc.nist.gov/ns/oscal/assessment/common#assessment_platforms>';
    }
    // define a constraint to limit retrieval to only those referenced by the parent
    constraintClause = `
    {
      SELECT DISTINCT ?iri
      WHERE {
          <${parent.iri}> a ${classTypeIri} ;
            ${predicate} ?iri .
      }
    }
    `;
  }

  return `
  SELECT DISTINCT ?iri ${selectionClause} 
  FROM <tag:stardog:api:context:local>
  WHERE {
    ?iri a <http://csrc.nist.gov/ns/oscal/assessment/common#AssessmentPlatform> . 
    ${predicates}
    ${constraintClause}
  }
  `
}
export const deleteAssessmentPlatformQuery = (id) => {
  const iri = `http://csrc.nist.gov/ns/oscal/assessment/common#AssessmentPlatform-${id}`;
  return deleteAssessmentPlatformByIriQuery(iri);
}
export const deleteAssessmentPlatformByIriQuery = (iri) => {
  return `
  DELETE {
    GRAPH <${iri}> {
      ?iri ?p ?o
    }
  } WHERE {
    GRAPH <${iri}> {
      ?iri a <http://csrc.nist.gov/ns/oscal/assessment/common#AssessmentPlatform> .
      ?iri ?p ?o
    }
  }
  `
}
export const attachToAssessmentPlatformQuery = (id, field, itemIris) => {
  const iri = `<http://csrc.nist.gov/ns/oscal/assessment/common#AssessmentPlatform-${id}>`;
  if (!assessmentPlatformPredicateMap.hasOwnProperty(field)) return null;
  const predicate = assessmentPlatformPredicateMap[field].predicate;
  let statements;
  if (Array.isArray(itemIris)) {
    statements = itemIris
      .map((itemIri) => `${iri} ${predicate} ${itemIri}`)
      .join(".\n        ")
    }
  else {
    if (!itemIris.startsWith('<')) itemIris = `<${itemIris}>`;
    statements = `${iri} ${predicate} ${itemIris}`;
  }
  return `
  INSERT DATA {
    GRAPH ${iri} {
      ${statements}
    }
  }
  `
}
export const detachFromAssessmentPlatformQuery = (id, field, itemIris) => {
  const iri = `<http://csrc.nist.gov/ns/oscal/assessment/common#AssessmentPlatform-${id}>`;
  if (!assessmentPlatformPredicateMap.hasOwnProperty(field)) return null;
  const predicate = assessmentPlatformPredicateMap[field].predicate;
  let statements;
  if (Array.isArray(itemIris)) {
    statements = itemIris
      .map((itemIri) => `${iri} ${predicate} ${itemIri}`)
      .join(".\n        ")
    }
  else {
    if (!itemIris.startsWith('<')) itemIris = `<${itemIris}>`;
    statements = `${iri} ${predicate} ${itemIris}`;
  }
  return `
  DELETE DATA {
    GRAPH ${iri} {
      ${statements}
    }
  }
  `
}

// AssessmentSubject support functions
export const insertAssessmentSubjectQuery = (propValues) => {
  const id = generateId( );

  // escape any special characters (e.g., newline)
  if (propValues.description !== undefined) {
    if (propValues.description.includes('\n')) propValues.description = propValues.description.replace(/\n/g, '\\n');
    if (propValues.description.includes('\"')) propValues.description = propValues.description.replace(/\"/g, '\\"');
    if (propValues.description.includes("\'")) propValues.description = propValues.description.replace(/\'/g, "\\'");
  }

  const iri = `<http://csrc.nist.gov/ns/oscal/assessment/common#AssessmentSubject-${id}>`;
  const insertPredicates = Object.entries(propValues)
      .filter((propPair) => assessmentSubjectPredicateMap.hasOwnProperty(propPair[0]))
      .map((propPair) => assessmentSubjectPredicateMap[propPair[0]].binding(iri, propPair[1]))
      .join('. \n      ');
  const query = `
  INSERT DATA {
    GRAPH ${iri} {
      ${iri} a <http://csrc.nist.gov/ns/oscal/assessment/common#AssessmentSubject> .
      ${iri} a <http://csrc.nist.gov/ns/oscal/common#ComplexDatatype> .
      ${iri} a <http://darklight.ai/ns/common#ComplexDatatype> .
      ${iri} <http://darklight.ai/ns/common#id> "${id}" .
      ${iri} <http://darklight.ai/ns/common#object_type> "assessment-subject" . 
      ${insertPredicates}
    }
  }
  `;
  return {iri, id, query}  
}
export const insertAssessmentSubjectsQuery = (assessmentSubjects) => {
  const graphs = [], subjectIris = [];
  assessmentSubjects.forEach((subject) => {
    const id = generateId( );

    // escape any special characters (e.g., newline)
    if (subject.description !== undefined) {
      if (subject.description.includes('\n')) subject.description = subject.description.replace(/\n/g, '\\n');
      if (subject.description.includes('\"')) subject.description = subject.description.replace(/\"/g, '\\"');
      if (subject.description.includes("\'")) subject.description = subject.description.replace(/\'/g, "\\'");
    }

    const insertPredicates = [];
    const iri = `<http://csrc.nist.gov/ns/oscal/assessment/common#AssessmentSubject-${id}>`;
    subjectIris.push(iri);
    insertPredicates.push(`${iri} a <http://csrc.nist.gov/ns/oscal/assessment/common#AssessmentSubject>`);
    insertPredicates.push(`${iri} a <http://csrc.nist.gov/ns/oscal/common#ComplexDatatype>`);
    insertPredicates.push(`${iri} a <http://darklight.ai/ns/common#ComplexDatatype>`);
    insertPredicates.push(`${iri} <http://darklight.ai/ns/common#id> "${id}"`);
    insertPredicates.push(`${iri} <http://darklight.ai/ns/common#object_type> "assessment-subject"`); 
    insertPredicates.push(`${iri} <http://csrc.nist.gov/ns/oscal/assessment/common#subject_type> "${subject.subject_type}"`);
    insertPredicates.push(`${iri} <http://csrc.nist.gov/ns/oscal/common#description> "${subject.description}"`);
    insertPredicates.push(`${iri} <http://csrc.nist.gov/ns/oscal/assessment/common#include_all> "${subject.include_all}"^^xsd:boolean`);
    insertPredicates.push(`${iri} <http://csrc.nist.gov/ns/oscal/assessment/common#include_subjects> "${subject.include_subjects}"`);
    insertPredicates.push(`${iri} <http://csrc.nist.gov/ns/oscal/assessment/common#exclude_subjects> "${subject.exclude_subjects}"`);
    graphs.push(`
  GRAPH ${iri} {
    ${insertPredicates.join(".\n        ")}
  }
    `)
  })
  const query = `
  INSERT DATA {
    ${graphs.join("\n")}
  }`;
  return {subjectIris, query};
}
export const selectAssessmentSubjectQuery = (id, select) => {
  return selectAssessmentSubjectByIriQuery(`http://csrc.nist.gov/ns/oscal/assessment/common#AssessmentSubject-${id}`, select);
}
export const selectAssessmentSubjectByIriQuery = (iri, select) => {
  if (!iri.startsWith('<')) iri = `<${iri}>`;
  if (select === undefined || select === null) select = Object.keys(assessmentSubjectPredicateMap);
  const { selectionClause, predicates } = buildSelectVariables(assessmentSubjectPredicateMap, select);
  return `
  SELECT ?iri ${selectionClause}
  FROM <tag:stardog:api:context:local>
  WHERE {
    BIND(${iri} AS ?iri)
    ?iri a <http://csrc.nist.gov/ns/oscal/assessment/common#AssessmentSubject> .
    ${predicates}
  }
  `
}
export const selectAllAssessmentSubjects = (select, args) => {
  if (select === undefined || select === null) select = Object.keys(assessmentSubjectPredicateMap);
  if (!select.includes('id')) select.push('id');

  if (args !== undefined ) {
    if ( args.filters !== undefined ) {
      for( const filter of args.filters) {
        if (!select.includes(filter.key)) select.push( filter.key );
      }
    }
    
    // add value of orderedBy's key to cause special predicates to be included
    if ( args.orderedBy !== undefined ) {
      if (!select.includes(args.orderedBy)) select.push(args.orderedBy);
    }
  }

  const { selectionClause, predicates } = buildSelectVariables(assessmentSubjectPredicateMap, select);
  return `
  SELECT DISTINCT ?iri ${selectionClause} 
  FROM <tag:stardog:api:context:local>
  WHERE {
    ?iri a <http://csrc.nist.gov/ns/oscal/assessment/common#AssessmentSubject> . 
    ${predicates}
  }
  `
}
export const deleteAssessmentSubjectQuery = (id) => {
  const iri = `http://csrc.nist.gov/ns/oscal/assessment/common#AssessmentSubject-${id}`;
  return deleteAssessmentSubjectByIriQuery(iri);
}
export const deleteAssessmentSubjectByIriQuery = (iri) => {
  return `
  DELETE {
    GRAPH <${iri}> {
      ?iri ?p ?o
    }
  } WHERE {
    GRAPH <${iri}> {
      ?iri a <http://csrc.nist.gov/ns/oscal/assessment/common#AssessmentSubject> .
      ?iri ?p ?o
    }
  }
  `
}
export const attachToAssessmentSubjectQuery = (id, field, itemIris) => {
  const iri = `<http://csrc.nist.gov/ns/oscal/assessment/common#AssessmentSubject-${id}>`;
  if (!assessmentSubjectPredicateMap.hasOwnProperty(field)) return null;
  const predicate = assessmentSubjectPredicateMap[field].predicate;
  let statements;
  if (Array.isArray(itemIris)) {
    statements = itemIris
      .map((itemIri) => `${iri} ${predicate} ${itemIri}`)
      .join(".\n        ")
    }
  else {
    if (!itemIris.startsWith('<')) itemIris = `<${itemIris}>`;
    statements = `${iri} ${predicate} ${itemIris}`;
  }
  return `
  INSERT DATA {
    GRAPH ${iri} {
      ${statements}
    }
  }
  `
}
export const detachFromAssessmentSubjectQuery = (id, field, itemIris) => {
  const iri = `<http://csrc.nist.gov/ns/oscal/assessment/common#AssessmentSubject-${id}>`;
  if (!assessmentSubjectPredicateMap.hasOwnProperty(field)) return null;
  const predicate = assessmentSubjectPredicateMap[field].predicate;
  let statements;
  if (Array.isArray(itemIris)) {
    statements = itemIris
      .map((itemIri) => `${iri} ${predicate} ${itemIri}`)
      .join(".\n        ")
    }
  else {
    if (!itemIris.startsWith('<')) itemIris = `<${itemIris}>`;
    statements = `${iri} ${predicate} ${itemIris}`;
  }
  return `
  DELETE DATA {
    GRAPH ${iri} {
      ${statements}
    }
  }
  `
}

// Associated Activity support functions
export const insertAssociatedActivityQuery = (propValues) => {
  // remove any object types from the list of propValues
  let taskId, roles, subjects;
  if (propValues.task_id !== undefined) {
    taskId = propValues.task_id;
    delete propValues.task_id;
  }
  if (propValues.roles !== undefined ) {
    roles = propValues.roles;
    delete propValues.roles;
  }
  if (propValues.subjects !== undefined) {
    subjects = propValues.subjects;
    delete propValues.subjects;
  }

  const id = generateId( );
  const iri = `<http://csrc.nist.gov/ns/oscal/assessment/common#AssociatedActivity-${id}>`;
  const insertPredicates = Object.entries(propValues)
      .filter((propPair) => associatedActivityPredicateMap.hasOwnProperty(propPair[0]))
      .map((propPair) => associatedActivityPredicateMap[propPair[0]].binding(iri, propPair[1]))
      .join('. \n      ');
  const query = `
  INSERT DATA {
    GRAPH ${iri} {
      ${iri} a <http://csrc.nist.gov/ns/oscal/assessment/common#AssociatedActivity> .
      ${iri} a <http://csrc.nist.gov/ns/oscal/common#ComplexDatatype> .
      ${iri} a <http://darklight.ai/ns/common#ComplexDatatype> .
      ${iri} <http://darklight.ai/ns/common#id> "${id}" .
      ${iri} <http://darklight.ai/ns/common#object_type> "associated-activity" . 
      ${insertPredicates}
    }
  }
  `;

  // restore previous PropValues
  if (taskId !== undefined) propValues.task_id = taskId;
  if (roles !== undefined ) propValues.roles = roles;
  if (subjects !== undefined) propValues.subjects = subjects;

  return {iri, id, query}  
}
export const selectAssociatedActivityQuery = (id, select) => {
  return selectAssociatedActivityByIriQuery(`http://csrc.nist.gov/ns/oscal/assessment/common#AssociatedActivity-${id}`, select);
}
export const selectAssociatedActivityByIriQuery = (iri, select) => {
  if (!iri.startsWith('<')) iri = `<${iri}>`;
  if (select === undefined || select === null) select = Object.keys(associatedActivityPredicateMap);
  const { selectionClause, predicates } = buildSelectVariables(associatedActivityPredicateMap, select);
  return `
  SELECT ?iri ${selectionClause}
  FROM <tag:stardog:api:context:local>
  WHERE {
    BIND(${iri} AS ?iri)
    ?iri a <http://csrc.nist.gov/ns/oscal/assessment/common#AssociatedActivity> .
    ${predicates}
  }
  `
}
export const selectAllAssociatedActivities = (select, args) => {
  if (select === undefined || select === null) select = Object.keys(associatedActivityPredicateMap);
  if (!select.includes('id')) select.push('id');

  if (args !== undefined ) {
    if ( args.filters !== undefined ) {
      for( const filter of args.filters) {
        if (!select.includes(filter.key)) select.push( filter.key );
      }
    }
    
    // add value of orderedBy's key to cause special predicates to be included
    if ( args.orderedBy !== undefined ) {
      if (!select.includes(args.orderedBy)) select.push(args.orderedBy);
    }
  }

  const { selectionClause, predicates } = buildSelectVariables(associatedActivityPredicateMap, select);
  return `
  SELECT DISTINCT ?iri ${selectionClause} 
  FROM <tag:stardog:api:context:local>
  WHERE {
    ?iri a <http://csrc.nist.gov/ns/oscal/assessment/common#AssociatedActivity> . 
    ${predicates}
  }
  `
}
export const deleteAssociatedActivityQuery = (id) => {
  const iri = `http://csrc.nist.gov/ns/oscal/assessment/common#AssociatedActivity-${id}`;
  return deleteAssociatedActivityByIriQuery(iri);
}
export const deleteAssociatedActivityByIriQuery = (iri) => {
  return `
  DELETE {
    GRAPH <${iri}> {
      ?iri ?p ?o
    }
  } WHERE {
    GRAPH <${iri}> {
      ?iri a <http://csrc.nist.gov/ns/oscal/assessment/common#AssociatedActivity> .
      ?iri ?p ?o
    }
  }
  `
}
export const attachToAssociatedActivityQuery = (id, field, itemIris) => {
  const iri = `<http://csrc.nist.gov/ns/oscal/assessment/common#AssociatedActivity-${id}>`;
  if (!associatedActivityPredicateMap.hasOwnProperty(field)) return null;
  const predicate = associatedActivityPredicateMap[field].predicate;
  let statements;
  if (Array.isArray(itemIris)) {
    statements = itemIris
      .map((itemIri) => `${iri} ${predicate} ${itemIri}`)
      .join(".\n        ")
    }
  else {
    if (!itemIris.startsWith('<')) itemIris = `<${itemIris}>`;
    statements = `${iri} ${predicate} ${itemIris}`;
  }
  return `
  INSERT DATA {
    GRAPH ${iri} {
      ${statements}
    }
  }
  `
}
export const detachFromAssociatedActivityQuery = (id, field, itemIris) => {
  const iri = `<http://csrc.nist.gov/ns/oscal/assessment/common#AssociatedActivity-${id}>`;
  if (!associatedActivityPredicateMap.hasOwnProperty(field)) return null;
  const predicate = associatedActivityPredicateMap[field].predicate;
  let statements;
  if (Array.isArray(itemIris)) {
    statements = itemIris
      .map((itemIri) => `${iri} ${predicate} ${itemIri}`)
      .join(".\n        ")
    }
  else {
    if (!itemIris.startsWith('<')) itemIris = `<${itemIris}>`;
    statements = `${iri} ${predicate} ${itemIris}`;
  }
  return `
  DELETE DATA {
    GRAPH ${iri} {
      ${statements}
    }
  }
  `
}

// Characterization support functions
export const insertCharacterizationQuery = (propValues) => {
  // remove any object types from the list of propValues
  let facets, origins, riskId;
  if (propValues.facets !== undefined) {
    facets = propValues.facets;
    delete propValues.facets;
  }
  if (propValues.origins !== undefined) {
    origins = propValues.origins;
    delete propValues.origins;
  }
  if (propValues.risk_id !== undefined) {
    riskId = propValues.risk_id;
    delete propValues.risk_id;
  }

  const id_material = {
    ...(origins[0].origin_actors[0].actor_type && {"actor_type": origins[0].origin_actors[0].actor_type}),
    ...(origins[0].origin_actors[0].actor_ref && {"actor_ref": origins[0].origin_actors[0].actor_ref}),
    ...(riskId && {"risk_id": riskId}),
  } ;
  const id = generateId( id_material, OSCAL_NS );
  const timestamp = new Date().toISOString()
  const iri = `<http://csrc.nist.gov/ns/oscal/assessment/common#Characterization-${id}>`;
  const insertPredicates = Object.entries(propValues)
      .filter((propPair) => characterizationPredicateMap.hasOwnProperty(propPair[0]))
      .map((propPair) => characterizationPredicateMap[propPair[0]].binding(iri, propPair[1]))
      .join('. \n      ');
  const query = `
  INSERT DATA {
    GRAPH ${iri} {
      ${iri} a <http://csrc.nist.gov/ns/oscal/assessment/common#Characterization> .
      ${iri} a <http://csrc.nist.gov/ns/oscal/common#ComplexDatatype> .
      ${iri} a <http://darklight.ai/ns/common#ComplexDatatype> .
      ${iri} <http://darklight.ai/ns/common#id> "${id}".
      ${iri} <http://darklight.ai/ns/common#object_type> "characterization" . 
      ${iri} <http://darklight.ai/ns/common#created> "${timestamp}"^^xsd:dateTime . 
      ${iri} <http://darklight.ai/ns/common#modified> "${timestamp}"^^xsd:dateTime . 
      ${insertPredicates}
    }
  }
  `;

  // restore the propValues passed in
  if (origins !== undefined) propValues.origins = origins;
  if (facets !== undefined) propValues.facets = facets;
  if (riskId !== undefined) propValues.risk_id = riskId;

  return {iri, id, query}  
}
export const selectCharacterizationQuery = (id, select) => {
  return selectCharacterizationByIriQuery(`http://csrc.nist.gov/ns/oscal/assessment/common#Characterization-${id}`, select);
}
export const selectCharacterizationByIriQuery = (iri, select) => {
  if (!iri.startsWith('<')) iri = `<${iri}>`;
  if (select === undefined || select === null) select = Object.keys(characterizationPredicateMap);
  const { selectionClause, predicates } = buildSelectVariables(characterizationPredicateMap, select);
  return `
  SELECT ?iri ${selectionClause}
  FROM <tag:stardog:api:context:local>
  WHERE {
    BIND(${iri} AS ?iri)
    ?iri a <http://csrc.nist.gov/ns/oscal/assessment/common#Characterization> .
    ${predicates}
  }
  `
}
export const selectAllCharacterizations = (select, args) => {
  if (select === undefined || select === null) select = Object.keys(characterizationPredicateMap);
  if (!select.includes('id')) select.push('id');

  if (args !== undefined ) {
    if ( args.filters !== undefined ) {
      for( const filter of args.filters) {
        if (!select.includes(filter.key)) select.push( filter.key );
      }
    }
    
    // add value of orderedBy's key to cause special predicates to be included
    if ( args.orderedBy !== undefined ) {
      if (!select.includes(args.orderedBy)) select.push(args.orderedBy);
    }
  }

  const { selectionClause, predicates } = buildSelectVariables(characterizationPredicateMap, select);
  return `
  SELECT DISTINCT ?iri ${selectionClause} 
  FROM <tag:stardog:api:context:local>
  WHERE {
    ?iri a <http://csrc.nist.gov/ns/oscal/assessment/common#Characterization> . 
    ${predicates}
  }
  `
}
export const deleteCharacterizationQuery = (id) => {
  const iri = `http://csrc.nist.gov/ns/oscal/assessment/common#Characterization-${id}`;
  return deleteCharacterizationByIriQuery(iri);
}
export const deleteCharacterizationByIriQuery = (iri) => {
  return `
  DELETE {
    GRAPH <${iri}> {
      ?iri ?p ?o
    }
  } WHERE {
    GRAPH <${iri}> {
      ?iri a <http://csrc.nist.gov/ns/oscal/assessment/common#Characterization> .
      ?iri ?p ?o
    }
  }
  `
}
export const attachToCharacterizationQuery = (id, field, itemIris) => {
  const iri = `<http://csrc.nist.gov/ns/oscal/assessment/common#Characterization-${id}>`;
  if (!characterizationPredicateMap.hasOwnProperty(field)) return null;
  const predicate = characterizationPredicateMap[field].predicate;
  let statements;
  if (Array.isArray(itemIris)) {
    statements = itemIris
      .map((itemIri) => `${iri} ${predicate} ${itemIri}`)
      .join(".\n        ")
    }
  else {
    if (!itemIris.startsWith('<')) itemIris = `<${itemIris}>`;
    statements = `${iri} ${predicate} ${itemIris}`;
  }
  return `
  INSERT DATA {
    GRAPH ${iri} {
      ${statements}
    }
  }
  `
}
export const detachFromCharacterizationQuery = (id, field, itemIris) => {
  const iri = `<http://csrc.nist.gov/ns/oscal/assessment/common#Characterization-${id}>`;
  if (!characterizationPredicateMap.hasOwnProperty(field)) return null;
  const predicate = characterizationPredicateMap[field].predicate;
  let statements;
  if (Array.isArray(itemIris)) {
    statements = itemIris
      .map((itemIri) => `${iri} ${predicate} ${itemIri}`)
      .join(".\n        ")
    }
  else {
    if (!itemIris.startsWith('<')) itemIris = `<${itemIris}>`;
    statements = `${iri} ${predicate} ${itemIris}`;
  }
  return `
  DELETE DATA {
    GRAPH ${iri} {
      ${statements}
    }
  }
  `
}

// Evidence support functions
export const insertEvidenceQuery = (propValues) => {
  // remove any object types from the list of propValues
  let observationId;
  if (propValues.observation_id !== undefined) {
    observationId = propValues.observation_id;
    delete propValues.observation_id;
  }

  const id = generateId( );
  const timestamp = new Date().toISOString();

  // escape any special characters (e.g., newline)
  if (propValues.description !== undefined) {
    if (propValues.description.includes('\n')) propValues.description = propValues.description.replace(/\n/g, '\\n');
    if (propValues.description.includes('\"')) propValues.description = propValues.description.replace(/\"/g, '\\"');
    if (propValues.description.includes("\'")) propValues.description = propValues.description.replace(/\'/g, "\\'");
  }

  const iri = `<http://csrc.nist.gov/ns/oscal/assessment/common#Evidence-${id}>`;
  const insertPredicates = Object.entries(propValues)
      .filter((propPair) => evidencePredicateMap.hasOwnProperty(propPair[0]))
      .map((propPair) => evidencePredicateMap[propPair[0]].binding(iri, propPair[1]))
      .join('. \n      ');
  const query = `
  INSERT DATA {
    GRAPH ${iri} {
      ${iri} a <http://csrc.nist.gov/ns/oscal/assessment/common#Evidence> .
      ${iri} a <http://csrc.nist.gov/ns/oscal/common#ComplexDatatype> .
      ${iri} a <http://darklight.ai/ns/common#ComplexDatatype> .
      ${iri} <http://darklight.ai/ns/common#id> "${id}" .
      ${iri} <http://darklight.ai/ns/common#object_type> "evidence" . 
      ${iri} <http://darklight.ai/ns/common#created> "${timestamp}"^^xsd:dateTime . 
      ${iri} <http://darklight.ai/ns/common#modified> "${timestamp}"^^xsd:dateTime . 
      ${insertPredicates}
    }
  }
  `;

  // restore the propValues passed in
  if (observationId !== undefined) propValues.observation_id = observationId;
  
  return {iri, id, query}  
}
export const insertEvidencesQuery = (evidences) => {
  const graphs = [], evidenceIris = [];
  evidences.forEach((evidence) => {
    const id = generateId( );
    const timestamp = new Date().toISOString();

    // escape any special characters (e.g., newline)
    if (evidence.description !== undefined) {
      if (evidence.description.includes('\n')) evidence.description = evidence.description.replace(/\n/g, '\\n');
      if (evidence.description.includes('\"')) evidence.description = evidence.description.replace(/\"/g, '\\"');
      if (evidence.description.includes("\'")) evidence.description = evidence.description.replace(/\'/g, "\\'");
    }

    const insertPredicates = [];
    const iri = `<http://csrc.nist.gov/ns/oscal/assessment/common#Evidence-${id}>`;
    evidenceIris.push(iri);
    insertPredicates.push(`${iri} a <http://csrc.nist.gov/ns/oscal/assessment/common#Evidence>`);
    insertPredicates.push(`${iri} a <http://csrc.nist.gov/ns/oscal/common#ComplexDatatype>`);
    insertPredicates.push(`${iri} a <http://darklight.ai/ns/common#ComplexDatatype>`);
    insertPredicates.push(`${iri} <http://darklight.ai/ns/common#id> "${id}"`);
    insertPredicates.push(`${iri} <http://darklight.ai/ns/common#object_type> "evidence"`); 
    insertPredicates.push(`${iri} <http://darklight.ai/ns/common#created> "${timestamp}"^^xsd:dateTime`);
    insertPredicates.push(`${iri} <http://darklight.ai/ns/common#modified> "${timestamp}"^^xsd:dateTime `);
    insertPredicates.push(`${iri} <http://csrc.nist.gov/ns/oscal/common#href> "${evidence.href}"^^xsd:anyURI`);
    insertPredicates.push(`${iri} <http://csrc.nist.gov/ns/oscal/common#description> "${evidence.description}"`);
    graphs.push(`
  GRAPH ${iri} {
    ${insertPredicates.join(".\n        ")}
  }
    `)
  })
  const query = `
  INSERT DATA {
    ${graphs.join("\n")}
  }`;
  return {evidenceIris, query};
}
export const selectEvidenceQuery = (id, select) => {
  return selectEvidenceByIriQuery(`http://csrc.nist.gov/ns/oscal/assessment/common#Evidence-${id}`, select);
}
export const selectEvidenceByIriQuery = (iri, select) => {
  if (!iri.startsWith('<')) iri = `<${iri}>`;
  if (select === undefined || select === null) select = Object.keys(evidencePredicateMap);

  const { selectionClause, predicates } = buildSelectVariables(evidencePredicateMap, select);
  return `
  SELECT ?iri ${selectionClause}
  FROM <tag:stardog:api:context:local>
  WHERE {
    BIND(${iri} AS ?iri)
    ?iri a <http://csrc.nist.gov/ns/oscal/assessment/common#Evidence> .
    ${predicates}
  }
  `
}
export const selectAllEvidence = (select, args, parent) => {
  let constraintClause = '';
  if (select === undefined || select === null) select = Object.keys(evidencePredicateMap);
  if (!select.includes('id')) select.push('id');

  if (args !== undefined ) {
    if ( args.filters !== undefined ) {
      for( const filter of args.filters) {
        if (!select.includes(filter.key)) select.push( filter.key );
      }
    }
    
    // add value of orderedBy's key to cause special predicates to be included
    if ( args.orderedBy !== undefined ) {
      if (!select.includes(args.orderedBy)) select.push(args.orderedBy);
    }
  }

  const { selectionClause, predicates } = buildSelectVariables(evidencePredicateMap, select);
  // add constraint clause to limit to those that are referenced by the specified object
  if (parent !== undefined && parent.iri !== undefined) {
    // define a constraint to limit retrieval to only those referenced by the parent
    constraintClause = `
    {
      SELECT DISTINCT ?iri
      WHERE {
          <${parent.iri}> a <http://csrc.nist.gov/ns/oscal/assessment/common#Observation> ;
            <http://csrc.nist.gov/ns/oscal/assessment/common#relevant_evidence> ?iri .
      }
    }
    `;
  }

  return `
  SELECT DISTINCT ?iri ${selectionClause} 
  FROM <tag:stardog:api:context:local>
  WHERE {
    ?iri a <http://csrc.nist.gov/ns/oscal/assessment/common#Evidence> . 
    ${predicates}
    ${constraintClause}
  }
  `
}
export const deleteEvidenceQuery = (id) => {
  const iri = `http://csrc.nist.gov/ns/oscal/assessment/common#Evidence-${id}`;
  return deleteEvidenceByIriQuery(iri);
}
export const deleteEvidenceByIriQuery = (iri) => {
  return `
  DELETE {
    GRAPH <${iri}> {
      ?iri ?p ?o
    }
  } WHERE {
    GRAPH <${iri}> {
      ?iri a <http://csrc.nist.gov/ns/oscal/assessment/common#Evidence> .
      ?iri ?p ?o
    }
  }
  `
}
export const attachToEvidenceQuery = (id, field, itemIris) => {
  const iri = `<http://csrc.nist.gov/ns/oscal/assessment/common#Evidence-${id}>`;
  if (!evidencePredicateMap.hasOwnProperty(field)) return null;
  const predicate = evidencePredicateMap[field].predicate;
  let statements;
  if (Array.isArray(itemIris)) {
    statements = itemIris
      .map((itemIri) => `${iri} ${predicate} ${itemIri}`)
      .join(".\n        ")
    }
  else {
    if (!itemIris.startsWith('<')) itemIris = `<${itemIris}>`;
    statements = `${iri} ${predicate} ${itemIris}`;
  }
  return `
  INSERT DATA {
    GRAPH ${iri} {
      ${statements}
    }
  }
  `
}
export const detachFromEvidenceQuery = (id, field, itemIris) => {
  const iri = `<http://csrc.nist.gov/ns/oscal/assessment/common#Evidence-${id}>`;
  if (!evidencePredicateMap.hasOwnProperty(field)) return null;
  const predicate = evidencePredicateMap[field].predicate;
  let statements;
  if (Array.isArray(itemIris)) {
    statements = itemIris
      .map((itemIri) => `${iri} ${predicate} ${itemIri}`)
      .join(".\n        ")
    }
  else {
    if (!itemIris.startsWith('<')) itemIris = `<${itemIris}>`;
    statements = `${iri} ${predicate} ${itemIris}`;
  }
  return `
  DELETE DATA {
    GRAPH ${iri} {
      ${statements}
    }
  }
  `
}

// Facet support functions
export const insertFacetQuery = (propValues) => {
  let characterizationId;
  if (propValues.characterization_id !== undefined) {
    characterizationId = propValues.characterization_id;
    delete propValues.characterization_id;
  }

  const id = generateId( );
  const timestamp = new Date().toISOString()
  const iri = `<http://csrc.nist.gov/ns/oscal/assessment/common#Facet-${id}>`;
  const insertPredicates = Object.entries(propValues)
      .filter((propPair) => facetPredicateMap.hasOwnProperty(propPair[0]))
      .map((propPair) => facetPredicateMap[propPair[0]].binding(iri, propPair[1]))
      .join('. \n      ');
  const query = `
  INSERT DATA {
    GRAPH ${iri} {
      ${iri} a <http://csrc.nist.gov/ns/oscal/assessment/common#Facet> .
      ${iri} a <http://csrc.nist.gov/ns/oscal/common#ComplexDatatype> .
      ${iri} a <http://darklight.ai/ns/common#ComplexDatatype> .
      ${iri} <http://darklight.ai/ns/common#id> "${id}" .
      ${iri} <http://darklight.ai/ns/common#object_type> "facet" . 
      ${iri} <http://darklight.ai/ns/common#created> "${timestamp}"^^xsd:dateTime . 
      ${iri} <http://darklight.ai/ns/common#modified> "${timestamp}"^^xsd:dateTime . 
      ${insertPredicates}
    }
  }
  `;

  // restore the previous PropValue values
  if (characterizationId !== undefined) propValues.characterization_id = characterizationId;

  return {iri, id, query}  
}
export const insertFacetsQuery = (facets) => {
  const graphs = [], facetIris = [];
  facets.forEach((facet) => {
    const id = generateId( );
    const timestamp = new Date().toISOString();
    const insertPredicates = [];
    const iri = `<http://csrc.nist.gov/ns/oscal/assessment/common#Facet-${id}>`;
    facetIris.push(iri);
    insertPredicates.push(`${iri} a <http://csrc.nist.gov/ns/oscal/assessment/common#Facet>`);
    insertPredicates.push(`${iri} a <http://csrc.nist.gov/ns/oscal/common#ComplexDatatype>`);
    insertPredicates.push(`${iri} a <http://darklight.ai/ns/common#ComplexDatatype>`);
    insertPredicates.push(`${iri} <http://darklight.ai/ns/common#id> "${id}"`);
    insertPredicates.push(`${iri} <http://darklight.ai/ns/common#object_type> "facet"`); 
    insertPredicates.push(`${iri} <http://darklight.ai/ns/common#created> "${timestamp}"^^xsd:dateTime`);
    insertPredicates.push(`${iri} <http://darklight.ai/ns/common#modified> "${timestamp}"^^xsd:dateTime `);
    insertPredicates.push(`${iri} <http://csrc.nist.gov/ns/oscal/assessment/common#risk_state> "${facet.risk_state}"`);
    insertPredicates.push(`${iri} <http://csrc.nist.gov/ns/oscal/common#source_system> "${facet.source_system}"^^xsd:anyURI`);
    insertPredicates.push(`${iri} <http://csrc.nist.gov/ns/oscal/assessment/common#facet_name> "${facet.facet_name}"`);
    insertPredicates.push(`${iri} <http://csrc.nist.gov/ns/oscal/assessment/common#facet_value> "${facet.facet_value}"`);
    graphs.push(`
  GRAPH ${iri} {
    ${insertPredicates.join(".\n        ")}
  }
    `)
  })
  const query = `
  INSERT DATA {
    ${graphs.join("\n")}
  }`;
  return {facetIris, query};
}
export const selectFacetQuery = (id, select) => {
  return selectFacetByIriQuery(`http://csrc.nist.gov/ns/oscal/assessment/common#Facet-${id}`, select);
}
export const selectFacetByIriQuery = (iri, select) => {
  if (!iri.startsWith('<')) iri = `<${iri}>`;
  let predicateMap = facetPredicateMap;
  if (iri.includes('VulnerabilityFacet')) predicateMap = vulnerabilityFacetPredicateMap;
  if (iri.includes('OscalFacet')) predicateMap = oscalFacetPredicateMap;
  if (iri.includes('FedrampFacet')) predicateMap = fedrampFacetPredicateMap;
  if (select === undefined || select === null) select = Object.keys(predicateMap);

  const { selectionClause, predicates } = buildSelectVariables(predicateMap, select);
  return `
  SELECT ?iri ${selectionClause}
  FROM <tag:stardog:api:context:local>
  WHERE {
    BIND(${iri} AS ?iri)
    ?iri a <http://csrc.nist.gov/ns/oscal/assessment/common#Facet> .
    ${predicates}
  }
  `
}
export const selectAllFacets = (select, args) => {
  if (select === undefined || select === null) select = Object.keys(facetPredicateMap);
  if (!select.includes('id')) select.push('id');

  if (args !== undefined ) {
    if ( args.filters !== undefined ) {
      for( const filter of args.filters) {
        if (!select.includes(filter.key)) select.push( filter.key );
      }
    }
    
    // add value of orderedBy's key to cause special predicates to be included
    if ( args.orderedBy !== undefined ) {
      if (!select.includes(args.orderedBy)) select.push(args.orderedBy);
    }
  }

  const { selectionClause, predicates } = buildSelectVariables(facetPredicateMap, select);
  return `
  SELECT DISTINCT ?iri ${selectionClause} 
  FROM <tag:stardog:api:context:local>
  WHERE {
    ?iri a <http://csrc.nist.gov/ns/oscal/assessment/common#Facet> . 
    ${predicates}
  }
  `
}
export const deleteFacetQuery = (id) => {
  const iri = `http://csrc.nist.gov/ns/oscal/assessment/common#Facet-${id}`;
  return deleteFacetByIriQuery(iri);
}
export const deleteFacetByIriQuery = (iri) => {
  return `
  DELETE {
    GRAPH <${iri}> {
      ?iri ?p ?o
    }
  } WHERE {
    GRAPH <${iri}> {
      ?iri a <http://csrc.nist.gov/ns/oscal/assessment/common#Facet> .
      ?iri ?p ?o
    }
  }
  `
}
export const attachToFacetQuery = (id, field, itemIris) => {
  const iri = `<http://csrc.nist.gov/ns/oscal/assessment/common#Facet-${id}>`;
  if (!facetPredicateMap.hasOwnProperty(field)) return null;
  const predicate = facetPredicateMap[field].predicate;
  let statements;
  if (Array.isArray(itemIris)) {
    statements = itemIris
      .map((itemIri) => `${iri} ${predicate} ${itemIri}`)
      .join(".\n        ")
    }
  else {
    if (!itemIris.startsWith('<')) itemIris = `<${itemIris}>`;
    statements = `${iri} ${predicate} ${itemIris}`;
  }
  return `
  INSERT DATA {
    GRAPH ${iri} {
      ${statements}
    }
  }
  `
}
export const detachFromFacetQuery = (id, field, itemIris) => {
  const iri = `<http://csrc.nist.gov/ns/oscal/assessment/common#Facet-${id}>`;
  if (!facetPredicateMap.hasOwnProperty(field)) return null;
  const predicate = facetPredicateMap[field].predicate;
  let statements;
  if (Array.isArray(itemIris)) {
    statements = itemIris
      .map((itemIri) => `${iri} ${predicate} ${itemIri}`)
      .join(".\n        ")
    }
  else {
    if (!itemIris.startsWith('<')) itemIris = `<${itemIris}>`;
    statements = `${iri} ${predicate} ${itemIris}`;
  }
  return `
  DELETE DATA {
    GRAPH ${iri} {
      ${statements}
    }
  }
  `
}

// LogEntryAuthor support functions
export const insertLogEntryAuthorQuery = (propValues) => {
  const id = generateId( );
  const iri = `<http://csrc.nist.gov/ns/oscal/assessment/common#LogEntryAuthor-${id}>`;
  const insertPredicates = Object.entries(propValues)
      .filter((propPair) => logEntryAuthorPredicateMap.hasOwnProperty(propPair[0]))
      .map((propPair) => logEntryAuthorPredicateMap[propPair[0]].binding(iri, propPair[1]))
      .join('. \n      ');
  const query = `
  INSERT DATA {
    GRAPH ${iri} {
      ${iri} a <http://csrc.nist.gov/ns/oscal/assessment/common#LogEntryAuthor> .
      ${iri} a <http://csrc.nist.gov/ns/oscal/common#ComplexDatatype> .
      ${iri} a <http://darklight.ai/ns/common#ComplexDatatype> .
      ${iri} <http://darklight.ai/ns/common#id> "${id}" .
      ${iri} <http://darklight.ai/ns/common#object_type> "log-entry-author" . 
      ${insertPredicates}
    }
  }
  `;
  return {iri, id, query}  
}
export const insertLogEntryAuthorsQuery = (authors) => {
  const graphs = [], authorIris = [];
  authors.forEach((author) => {
    if (author.party === undefined) throw new CyioError(`Party ID not specified for LogEntryAuthor`); 
    const id = generateId( );
    const insertPredicates = [];
    const iri = `<http://csrc.nist.gov/ns/oscal/assessment/common#LogEntryAuthor-${id}>`;
    authorIris.push(iri);
    insertPredicates.push(`${iri} a <http://csrc.nist.gov/ns/oscal/assessment/common#LogEntryAuthor>`);
    insertPredicates.push(`${iri} a <http://csrc.nist.gov/ns/oscal/common#ComplexDatatype>`);
    insertPredicates.push(`${iri} a <http://darklight.ai/ns/common#ComplexDatatype>`);
    insertPredicates.push(`${iri} <http://darklight.ai/ns/common#id> "${id}"`);
    insertPredicates.push(`${iri} <http://darklight.ai/ns/common#object_type> "log-entry-author"`); 
    insertPredicates.push(`${iri} <http://csrc.nist.gov/ns/oscal/common#party> <http://csrc.nist.gov/ns/oscal/common#Party-${author.party}>`);
    if (author.role != undefined) {
      insertPredicates.push(`${iri} <http://csrc.nist.gov/ns/oscal/common#role> <http://csrc.nist.gov/ns/oscal/common#Role-${author.role}>`);
    }

    graphs.push(`
  GRAPH ${iri} {
    ${insertPredicates.join(".\n        ")}
  }
    `)
  })
  const query = `
  INSERT DATA {
    ${graphs.join("\n")}
  }`;
  return {authorIris, query};
}
export const selectLogEntryAuthorQuery = (id, select) => {
  return selectLogEntryAuthorByIriQuery(`http://csrc.nist.gov/ns/oscal/assessment/common#LogEntryAuthor-${id}`, select);
}
export const selectLogEntryAuthorByIriQuery = (iri, select) => {
  if (!iri.startsWith('<')) iri = `<${iri}>`;
  if (select === undefined || select === null) select = Object.keys(logEntryAuthorPredicateMap);
  if (select.includes('party')) {
    select.push('party_name');
    select.push('party_type');
  }

  const { selectionClause, predicates } = buildSelectVariables(logEntryAuthorPredicateMap, select);
  return `
  SELECT ?iri ${selectionClause}
  FROM <tag:stardog:api:context:local>
  WHERE {
    BIND(${iri} AS ?iri)
    ?iri a <http://csrc.nist.gov/ns/oscal/assessment/common#LogEntryAuthor> .
    ${predicates}
  }
  `
}
export const selectAllLogEntryAuthors = (select, args) => {
  if (select === undefined || select === null) select = Object.keys(logEntryAuthorPredicateMap);
  if (!select.includes('id')) select.push('id');
  if (select.includes('party')) {
    select.push('party_name');
    select.push('party_type');
  }

  if (args !== undefined ) {
    if ( args.filters !== undefined ) {
      for( const filter of args.filters) {
        if (!select.includes(filter.key)) select.push( filter.key );
      }
    }
    
    // add value of orderedBy's key to cause special predicates to be included
    if ( args.orderedBy !== undefined ) {
      if (!select.includes(args.orderedBy)) select.push(args.orderedBy);
    }
  }

  const { selectionClause, predicates } = buildSelectVariables(logEntryAuthorPredicateMap, select);
  return `
  SELECT DISTINCT ?iri ${selectionClause} 
  FROM <tag:stardog:api:context:local>
  WHERE {
    ?iri a <http://csrc.nist.gov/ns/oscal/assessment/common#LogEntryAuthor> . 
    ${predicates}
  }
  `
}
export const deleteLogEntryAuthorQuery = (id) => {
  const iri = `http://csrc.nist.gov/ns/oscal/assessment/common#LogEntryAuthor-${id}`;
  return deleteLogEntryAuthorByIriQuery(iri);
}
export const deleteLogEntryAuthorByIriQuery = (iri) => {
  return `
  DELETE {
    GRAPH <${iri}> {
      ?iri ?p ?o
    }
  } WHERE {
    GRAPH <${iri}> {
      ?iri a <http://csrc.nist.gov/ns/oscal/assessment/common#LogEntryAuthor> .
      ?iri ?p ?o
    }
  }
  `
}
export const attachToLogEntryAuthorQuery = (id, field, itemIris) => {
  const iri = `<http://csrc.nist.gov/ns/oscal/assessment/common#LogEntryAuthor-${id}>`;
  if (!logEntryAuthorPredicateMap.hasOwnProperty(field)) return null;
  const predicate = logEntryAuthorPredicateMap[field].predicate;
  let statements;
  if (Array.isArray(itemIris)) {
    statements = itemIris
      .map((itemIri) => `${iri} ${predicate} ${itemIri}`)
      .join(".\n        ")
    }
  else {
    if (!itemIris.startsWith('<')) itemIris = `<${itemIris}>`;
    statements = `${iri} ${predicate} ${itemIris}`;
  }
  return `
  INSERT DATA {
    GRAPH ${iri} {
      ${statements}
    }
  }
  `
}
export const detachFromLogEntryAuthorQuery = (id, field, itemIris) => {
  const iri = `<http://csrc.nist.gov/ns/oscal/assessment/common#LogEntryAuthor-${id}>`;
  if (!logEntryAuthorPredicateMap.hasOwnProperty(field)) return null;
  const predicate = logEntryAuthorPredicateMap[field].predicate;
  let statements;
  if (Array.isArray(itemIris)) {
    statements = itemIris
      .map((itemIri) => `${iri} ${predicate} ${itemIri}`)
      .join(".\n        ")
    }
  else {
    if (!itemIris.startsWith('<')) itemIris = `<${itemIris}>`;
    statements = `${iri} ${predicate} ${itemIris}`;
  }
  return `
  DELETE DATA {
    GRAPH ${iri} {
      ${statements}
    }
  }
  `
}

// Mitigating Factor support functions
export const insertMitigatingFactorQuery = (propValues) => {
  // remove any object types from the list of propValues
  let subjects, riskId;
  if (propValues.subjects !== undefined) {
    subjects = propValues.subjects;
    delete propValues.subjects;
  }
  if (propValues.risk_id !== undefined) {
    riskId = propValues.risk_id;
    delete propValues.risk_id;
  }

  const id_material = {
    ...(propValues.implementation && {"implementation": propValues.implementation}),
  } ;
  const id = generateId( id_material, OSCAL_NS );
  const timestamp = new Date().toISOString();

  // escape any special characters (e.g., newline)
  if (propValues.description !== undefined) {
    if (propValues.description.includes('\n')) propValues.description = propValues.description.replace(/\n/g, '\\n');
    if (propValues.description.includes('\"')) propValues.description = propValues.description.replace(/\"/g, '\\"');
    if (propValues.description.includes("\'")) propValues.description = propValues.description.replace(/\'/g, "\\'");
  }

  const iri = `<http://csrc.nist.gov/ns/oscal/assessment/common#MitigatingFactor-${id}>`;
  const insertPredicates = Object.entries(propValues)
      .filter((propPair) => mitigatingFactorPredicateMap.hasOwnProperty(propPair[0]))
      .map((propPair) => mitigatingFactorPredicateMap[propPair[0]].binding(iri, propPair[1]))
      .join('. \n      ');
  const query = `
  INSERT DATA {
    GRAPH ${iri} {
      ${iri} a <http://csrc.nist.gov/ns/oscal/assessment/common#MitigatingFactor> .
      ${iri} a <http://csrc.nist.gov/ns/oscal/common#Object> .
      ${iri} a <http://darklight.ai/ns/common#Object> .
      ${iri} <http://darklight.ai/ns/common#id> "${id}".
      ${iri} <http://darklight.ai/ns/common#object_type> "mitigating-factor" . 
      ${iri} <http://darklight.ai/ns/common#created> "${timestamp}"^^xsd:dateTime . 
      ${iri} <http://darklight.ai/ns/common#modified> "${timestamp}"^^xsd:dateTime . 
      ${insertPredicates}
    }
  }
  `;

  // restore the propValues passed in
  if (subjects !== undefined) propValues.subjects = subjects;
  if (riskId !== undefined) propValues.risk_id = riskId;

  return {iri, id, query}  
}
export const selectMitigatingFactorQuery = (id, select) => {
  return selectMitigatingFactorByIriQuery(`http://csrc.nist.gov/ns/oscal/assessment/common#MitigatingFactor-${id}`, select);
}
export const selectMitigatingFactorByIriQuery = (iri, select) => {
  if (!iri.startsWith('<')) iri = `<${iri}>`;
  if (select === undefined || select === null) select = Object.keys(mitigatingFactorPredicateMap);
  const { selectionClause, predicates } = buildSelectVariables(mitigatingFactorPredicateMap, select);
  return `
  SELECT ?iri ${selectionClause}
  FROM <tag:stardog:api:context:local>
  WHERE {
    BIND(${iri} AS ?iri)
    ?iri a <http://csrc.nist.gov/ns/oscal/assessment/common#MitigatingFactor> .
    ${predicates}
  }
  `
}
export const selectAllMitigatingFactors = (select, args) => {
  if (select === undefined || select === null) select = Object.keys(mitigatingFactorPredicateMap);
  if (!select.includes('id')) select.push('id');

  if (args !== undefined ) {
    if ( args.filters !== undefined ) {
      for( const filter of args.filters) {
        if (!select.includes(filter.key)) select.push( filter.key );
      }
    }
    
    // add value of orderedBy's key to cause special predicates to be included
    if ( args.orderedBy !== undefined ) {
      if (!select.includes(args.orderedBy)) select.push(args.orderedBy);
    }
  }

  const { selectionClause, predicates } = buildSelectVariables(mitigatingFactorPredicateMap, select);
  return `
  SELECT DISTINCT ?iri ${selectionClause} 
  FROM <tag:stardog:api:context:local>
  WHERE {
    ?iri a <http://csrc.nist.gov/ns/oscal/assessment/common#MitigatingFactor> . 
    ${predicates}
  }
  `
}
export const deleteMitigatingFactorQuery = (id) => {
  const iri = `http://csrc.nist.gov/ns/oscal/assessment/common#MitigatingFactor-${id}`;
  return deleteMitigatingFactorByIriQuery(iri);
}
export const deleteMitigatingFactorByIriQuery = (iri) => {
  return `
  DELETE {
    GRAPH <${iri}> {
      ?iri ?p ?o
    }
  } WHERE {
    GRAPH <${iri}> {
      ?iri a <http://csrc.nist.gov/ns/oscal/assessment/common#MitigatingFactor> .
      ?iri ?p ?o
    }
  }
  `
}
export const attachToMitigatingFactorQuery = (id, field, itemIris) => {
  const iri = `<http://csrc.nist.gov/ns/oscal/common#MitigatingFactor-${id}>`;
  if (!mitigatingFactorPredicateMap.hasOwnProperty(field)) return null;
  const predicate = mitigatingFactorPredicateMap[field].predicate;
  let statements;
  if (Array.isArray(itemIris)) {
    statements = itemIris
      .map((itemIri) => `${iri} ${predicate} ${itemIri}`)
      .join(".\n        ")
    }
  else {
    if (!itemIris.startsWith('<')) itemIris = `<${itemIris}>`;
    statements = `${iri} ${predicate} ${itemIris}`;
  }
  return `
  INSERT DATA {
    GRAPH ${iri} {
      ${statements}
    }
  }
  `
}
export const detachFromMitigatingFactorQuery = (id, field, itemIris) => {
  const iri = `<http://csrc.nist.gov/ns/oscal/common#MitigatingFactor-${id}>`;
  if (!mitigatingFactorPredicateMap.hasOwnProperty(field)) return null;
  const predicate = mitigatingFactorPredicateMap[field].predicate;
  let statements;
  if (Array.isArray(itemIris)) {
    statements = itemIris
      .map((itemIri) => `${iri} ${predicate} ${itemIri}`)
      .join(".\n        ")
    }
  else {
    if (!itemIris.startsWith('<')) itemIris = `<${itemIris}>`;
    statements = `${iri} ${predicate} ${itemIris}`;
  }
  return `
  DELETE DATA {
    GRAPH ${iri} {
      ${statements}
    }
  }
  `
}

// Observation support functions
export const insertObservationQuery = (propValues) => {
  const id_material = {
    //TODO: Need the actor_ref and actor_type
    ...(propValues.collected && {"collected": propValues.collected}),
    ...(propValues.methods && {"methods": propValues.methods}),
    ...(propValues.observation_types && {"observation_types": propValues.observation_types}),
    ...(propValues.name && {"name": propValues.name}),
  } ;
  const id = generateId( id_material, OSCAL_NS );
  const timestamp = new Date().toISOString();

  // escape any special characters (e.g., newline)
  if (propValues.description !== undefined) {
    if (propValues.description.includes('\n')) propValues.description = propValues.description.replace(/\n/g, '\\n');
    if (propValues.description.includes('\"')) propValues.description = propValues.description.replace(/\"/g, '\\"');
    if (propValues.description.includes("\'")) propValues.description = propValues.description.replace(/\'/g, "\\'");
  }

  const iri = `<http://csrc.nist.gov/ns/oscal/assessment/common#Observation-${id}>`;
  const insertPredicates = Object.entries(propValues)
      .filter((propPair) => observationPredicateMap.hasOwnProperty(propPair[0]))
      .map((propPair) => observationPredicateMap[propPair[0]].binding(iri, propPair[1]))
      .join('. \n      ');
  const query = `
  INSERT DATA {
    GRAPH ${iri} {
      ${iri} a <http://csrc.nist.gov/ns/oscal/assessment/common#Observation> .
      ${iri} a <http://csrc.nist.gov/ns/oscal/common#Object> .
      ${iri} a <http://darklight.ai/ns/common#Object> .
      ${iri} <http://darklight.ai/ns/common#id> "${id}".
      ${iri} <http://darklight.ai/ns/common#object_type> "observation" . 
      ${iri} <http://darklight.ai/ns/common#created> "${timestamp}"^^xsd:dateTime . 
      ${iri} <http://darklight.ai/ns/common#modified> "${timestamp}"^^xsd:dateTime . 
      ${insertPredicates}
    }
  }
  `;
  return {iri, id, query}
}
export const selectObservationQuery = (id, select) => {
  return selectObservationByIriQuery(`http://csrc.nist.gov/ns/oscal/assessment/common#Observation-${id}`, select);
}
export const selectObservationByIriQuery = (iri, select) => {
  if (!iri.startsWith('<')) iri = `<${iri}>`;
  if (select === undefined || select === null) select = Object.keys(observationPredicateMap);
  if (!select.includes('id')) select.push('id');
  const { selectionClause, predicates } = buildSelectVariables(observationPredicateMap, select);
  return `
  SELECT ?iri ${selectionClause}
  FROM <tag:stardog:api:context:local>
  WHERE {
    BIND(${iri} AS ?iri)
    ?iri a <http://csrc.nist.gov/ns/oscal/assessment/common#Observation> .
    ${predicates}
  }
  `
}
export const selectAllObservations = (select, args, parent) => {
  let constraintClause = '';
  if (select === undefined || select === null) select = Object.keys(observationPredicateMap);
  if (!select.includes('id')) select.push('id');

  if (args !== undefined ) {
    if ( args.filters !== undefined ) {
      for( const filter of args.filters) {
        if (!select.includes(filter.key)) select.push( filter.key );
      }
    }
    
    // add value of orderedBy's key to cause special predicates to be included
    if ( args.orderedBy !== undefined ) {
      if (!select.includes(args.orderedBy)) select.push(args.orderedBy);
    }
  }

  const { selectionClause, predicates } = buildSelectVariables(observationPredicateMap, select);
  // add constraint clause to limit to those that are referenced by the specified POAM
  if (parent !== undefined && parent.iri !== undefined) {
    let classTypeIri, predicate;
    if (parent.entity_type === 'poam') {
      classTypeIri = '<http://csrc.nist.gov/ns/oscal/common#POAM>';
      predicate = '<http://csrc.nist.gov/ns/oscal/poam#observations>';
    }
    if (parent.entity_type === 'poam-item') {
      classTypeIri = '<http://csrc.nist.gov/ns/oscal/poam#Item>';
      predicate = '<http://csrc.nist.gov/ns/oscal/assessment/common#related_observations>';
    }
    if (parent.entity_type === 'risk') {
      classTypeIri = '<http://csrc.nist.gov/ns/oscal/assessment/common#Risk>' ;
      predicate = '<http://csrc.nist.gov/ns/oscal/assessment/common#related_observations>';
    }
    if (parent.entity_type === 'result') {
      classTypeIri = '<http://csrc.nist.gov/ns/oscal/assessment-results#Result>';
      predicate = '<http://csrc.nist.gov/ns/oscal/assessment/common#observations>';
    }
    if (parent.entity_type === 'finding') {
      classTypeIri = '<http://csrc.nist.gov/ns/oscal/assessment-results#Finding>'
      predicate = '<http://csrc.nist.gov/ns/oscal/assessment/common#related_observations>';
    }
    // define a constraint to limit retrieval to only those referenced by the parent
    constraintClause = `
    {
      SELECT DISTINCT ?iri
      WHERE {
          <${parent.iri}> a ${classTypeIri} ;
            ${predicate} ?iri .
      }
    }
    `;
  }

  return `
  SELECT DISTINCT ?iri ${selectionClause} 
  FROM <tag:stardog:api:context:local>
  WHERE {
    ?iri a <http://csrc.nist.gov/ns/oscal/assessment/common#Observation> . 
    ${predicates}
    ${constraintClause}
  }
  `
}
export const deleteObservationQuery = (id) => {
  const iri = `http://csrc.nist.gov/ns/oscal/assessment/common#Observation-${id}`;
  return deleteObservationByIriQuery(iri);
}
export const deleteObservationByIriQuery = (iri) => {
  return `
  DELETE {
    GRAPH <${iri}> {
      ?iri ?p ?o
    }
  } WHERE {
    GRAPH <${iri}> {
      ?iri a <http://csrc.nist.gov/ns/oscal/assessment/common#Observation> .
      ?iri ?p ?o
    }
  }
  `
}
export const attachToObservationQuery = (id, field, itemIris) => {
  const iri = `<http://csrc.nist.gov/ns/oscal/assessment/common#Observation-${id}>`;
  if (!observationPredicateMap.hasOwnProperty(field)) return null;
  const predicate = observationPredicateMap[field].predicate;
  let statements;
  if (Array.isArray(itemIris)) {
    statements = itemIris
      .map((itemIri) => `${iri} ${predicate} ${itemIri}`)
      .join(".\n        ")
    }
  else {
    if (!itemIris.startsWith('<')) itemIris = `<${itemIris}>`;
    statements = `${iri} ${predicate} ${itemIris}`;
  }
  return `
  INSERT DATA {
    GRAPH ${iri} {
      ${statements}
    }
  }
  `
}
export const detachFromObservationQuery = (id, field, itemIris) => {
  const iri = `<http://csrc.nist.gov/ns/oscal/assessment/common#Observation-${id}>`;
  if (!observationPredicateMap.hasOwnProperty(field)) return null;
  const predicate = observationPredicateMap[field].predicate;
  let statements;
  if (Array.isArray(itemIris)) {
    statements = itemIris
      .map((itemIri) => `${iri} ${predicate} ${itemIri}`)
      .join(".\n        ")
    }
  else {
    if (!itemIris.startsWith('<')) itemIris = `<${itemIris}>`;
    statements = `${iri} ${predicate} ${itemIris}`;
  }
  return `
  DELETE DATA {
    GRAPH ${iri} {
      ${statements}
    }
  }
  `
}

// Origin support functions
export const insertOriginQuery = (propValues) => {
  let originActors, relatedTasks;
  if (propValues.origin_actors !== undefined) {
    originActors = propValues.origin_actors;
    delete propValues.origin_actors;
  }
  if (propValues.related_tasks !== undefined) {
    relatedTasks = propValues.related_tasks;
    delete propValues.related_tasks;
  }

  // compute the deterministic identifier
  const id_material = {
    ...(originActors[0].actor_type && {"actor_type": originActors[0].actor_type}),
    ...(originActors[0].actor_ref && {"actor_ref": originActors[0].actor_ref}),
  } ;
  const id = generateId( id_material, OSCAL_NS );

  const iri = `<http://csrc.nist.gov/ns/oscal/assessment/common#Origin-${id}>`;
  const insertPredicates = Object.entries(propValues)
      .filter((propPair) => originPredicateMap.hasOwnProperty(propPair[0]))
      .map((propPair) => originPredicateMap[propPair[0]].binding(iri, propPair[1]))
      .join('. \n      ');
  const query = `
  INSERT DATA {
    GRAPH ${iri} {
      ${iri} a <http://csrc.nist.gov/ns/oscal/assessment/common#Origin> .
      ${iri} a <http://csrc.nist.gov/ns/oscal/common#ComplexDatatype> .
      ${iri} a <http://darklight.ai/ns/common#ComplexDatatype> .
      ${iri} <http://darklight.ai/ns/common#id> "${id}" .
      ${iri} <http://darklight.ai/ns/common#object_type> "origin" . 
      ${insertPredicates}
    }
  }
  `;

  // restore the propValues
  if (originActors !== undefined) propValues.origin_actors = originActors;
  if (relatedTasks !== undefined) propValues.related_tasks = relatedTasks;

  return {iri, id, query}  
}
export const selectOriginQuery = (id, select) => {
  return selectOriginByIriQuery(`http://csrc.nist.gov/ns/oscal/assessment/common#Origin-${id}`, select);
}
export const selectOriginByIriQuery = (iri, select) => {
  if (!iri.startsWith('<')) iri = `<${iri}>`;
  if (select === undefined || select === null) select = Object.keys(originPredicateMap);
  const { selectionClause, predicates } = buildSelectVariables(originPredicateMap, select);
  return `
  SELECT ?iri ${selectionClause}
  FROM <tag:stardog:api:context:local>
  WHERE {
    BIND(${iri} AS ?iri)
    ?iri a <http://csrc.nist.gov/ns/oscal/assessment/common#Origin> .
    ${predicates}
  }
  `
}
export const selectAllOrigins = (select, args, parent) => {
  let constraintClause = '';
  if (select === undefined || select === null) select = Object.keys(originPredicateMap);
  if (!select.includes('id')) select.push('id');

  if (args !== undefined ) {
    if ( args.filters !== undefined ) {
      for( const filter of args.filters) {
        if (!select.includes(filter.key)) select.push( filter.key );
      }
    }
    
    // add value of orderedBy's key to cause special predicates to be included
    if ( args.orderedBy !== undefined ) {
      if (!select.includes(args.orderedBy)) select.push(args.orderedBy);
    }
  }

  const { selectionClause, predicates } = buildSelectVariables(originPredicateMap, select);
  // add constraint clause to limit to those that are referenced by the specified object
  if (parent !== undefined && parent.iri !== undefined) {
    let classTypeIri;
    if (parent.entity_type === 'characterization') {
      classTypeIri = '<http://csrc.nist.gov/ns/oscal/assessment/common#Characterization>';
    }
    if (parent.entity_type === 'observation') {
      classTypeIri = '<http://csrc.nist.gov/ns/oscal/assessment/common#Observation>';
    }
    if (parent.entity_type === 'risk') {
      classTypeIri = '<http://csrc.nist.gov/ns/oscal/assessment/common#Risk>';
    }
    if (parent.entity_type === 'risk-response') {
      classTypeIri = '<http://csrc.nist.gov/ns/oscal/assessment/common#RiskResponse>';
    }
    // define a constraint to limit retrieval to only those referenced by the parent
    constraintClause = `
    {
      SELECT DISTINCT ?iri
      WHERE {
          <${parent.iri}> a ${classTypeIri} ;
            <http://csrc.nist.gov/ns/oscal/assessment/common#origins> ?iri .
      }
    }
    `;
  }

  return `
  SELECT DISTINCT ?iri ${selectionClause} 
  FROM <tag:stardog:api:context:local>
  WHERE {
    ?iri a <http://csrc.nist.gov/ns/oscal/assessment/common#Origin> . 
    ${predicates}
    ${constraintClause}
  }
  `;
}
export const deleteOriginQuery = (id) => {
  const iri = `http://csrc.nist.gov/ns/oscal/assessment/common#Origin-${id}`;
  return deleteOriginByIriQuery(iri);
}
export const deleteOriginByIriQuery = (iri) => {
  return `
  DELETE {
    GRAPH <${iri}> {
      ?iri ?p ?o
    }
  } WHERE {
    GRAPH <${iri}> {
      ?iri a <http://csrc.nist.gov/ns/oscal/assessment/common#Origin> .
      ?iri ?p ?o
    }
  }
  `
}
export const attachToOriginQuery = (id, field, itemIris) => {
  const iri = `<http://csrc.nist.gov/ns/oscal/assessment/common#Origin-${id}>`;
  if (!originPredicateMap.hasOwnProperty(field)) return null;
  const predicate = originPredicateMap[field].predicate;
  let statements;
  if (Array.isArray(itemIris)) {
    statements = itemIris
      .map((itemIri) => `${iri} ${predicate} ${itemIri}`)
      .join(".\n        ")
    }
  else {
    if (!itemIris.startsWith('<')) itemIris = `<${itemIris}>`;
    statements = `${iri} ${predicate} ${itemIris}`;
  }
  return `
  INSERT DATA {
    GRAPH ${iri} {
      ${statements}
    }
  }
  `
}
export const detachFromOriginQuery = (id, field, itemIris) => {
  const iri = `<http://csrc.nist.gov/ns/oscal/assessment/common#Origin-${id}>`;
  if (!originPredicateMap.hasOwnProperty(field)) return null;
  const predicate = originPredicateMap[field].predicate;
  let statements;
  if (Array.isArray(itemIris)) {
    statements = itemIris
      .map((itemIri) => `${iri} ${predicate} ${itemIri}`)
      .join(".\n        ")
    }
  else {
    if (!itemIris.startsWith('<')) itemIris = `<${itemIris}>`;
    statements = `${iri} ${predicate} ${itemIris}`;
  }
  return `
  DELETE DATA {
    GRAPH ${iri} {
      ${statements}
    }
  }
  `
}

// Required Asset support functions
export const insertRequiredAssetQuery = (propValues) => {
  // remove any object types from the list of propValues
  let remediationId, subjects;
  if (propValues.remediation_id !== undefined) {
    remediationId = propValues.remediation_id;
    delete propValues.remediation_id
  }
  if (propValues.subjects !== undefined) {
    subjects = propValues.subjects;
    delete propValues.subjects;
  }

  const id_material = {
    ...(propValues.name && {"name": propValues.name}),
    ...(propValues.description && {"description": propValues.description}),
  } ;
  const id = generateId( id_material, OSCAL_NS );
  const timestamp = new Date().toISOString();

  // escape any special characters (e.g., newline)
  if (propValues.description !== undefined) {
    if (propValues.description.includes('\n')) propValues.description = propValues.description.replace(/\n/g, '\\n');
    if (propValues.description.includes('\"')) propValues.description = propValues.description.replace(/\"/g, '\\"');
    if (propValues.description.includes("\'")) propValues.description = propValues.description.replace(/\'/g, "\\'");
  }

  const iri = `<http://csrc.nist.gov/ns/oscal/assessment/common#RequiredAsset-${id}>`;
  const insertPredicates = Object.entries(propValues)
      .filter((propPair) => requiredAssetPredicateMap.hasOwnProperty(propPair[0]))
      .map((propPair) => requiredAssetPredicateMap[propPair[0]].binding(iri, propPair[1]))
      .join('. \n      ');
  const query = `
  INSERT DATA {
    GRAPH ${iri} {
      ${iri} a <http://csrc.nist.gov/ns/oscal/assessment/common#RequiredAsset> .
      ${iri} a <http://csrc.nist.gov/ns/oscal/common#Object> .
      ${iri} a <http://darklight.ai/ns/common#Object> .
      ${iri} <http://darklight.ai/ns/common#id> "${id}" .
      ${iri} <http://darklight.ai/ns/common#object_type> "required-asset" . 
      ${iri} <http://darklight.ai/ns/common#created> "${timestamp}"^^xsd:dateTime . 
      ${iri} <http://darklight.ai/ns/common#modified> "${timestamp}"^^xsd:dateTime . 
      ${insertPredicates}
    }
  }
  `;

  // restore the previous PropValue values
  if (remediationId !== undefined) propValues.remediation_id = remediationId;
  if (subjects !== undefined) propValues.subjects = subjects;

  return {iri, id, query}  
}
export const insertRequiredAssetsQuery = (requiredAssets) => {
  const graphs = [], reqAssetIris = [];
  requiredAssets.forEach((reqAsset) => {
    const id_material = {
      ...(reqAsset.name && {"name": reqAsset.name}),
      ...(reqAsset.description && {"description": reqAsset.description}),
    } ;
    const id = generateId( id_material, OSCAL_NS );
    const timestamp = new Date().toISOString();
  
    // escape any special characters (e.g., newline)
    if (reqAsset.description !== undefined) {
      if (reqAsset.description.includes('\n')) reqAsset.description = reqAsset.description.replace(/\n/g, '\\n');
      if (reqAsset.description.includes('\"')) reqAsset.description = reqAsset.description.replace(/\"/g, '\\"');
      if (reqAsset.description.includes("\'")) reqAsset.description = reqAsset.description.replace(/\'/g, "\\'");
    }

    const insertPredicates = [];
    const iri = `<http://csrc.nist.gov/ns/oscal/assessment/common#RequiredAsset-${id}>`;
    reqAssetIris.push(iri);
    insertPredicates.push(`${iri} a <http://csrc.nist.gov/ns/oscal/assessment/common#RequiredAsset>`);
    insertPredicates.push(`${iri} a <http://csrc.nist.gov/ns/oscal/common#Object>`);
    insertPredicates.push(`${iri} a <http://darklight.ai/ns/common#Object>`);
    insertPredicates.push(`${iri} <http://darklight.ai/ns/common#id> "${id}"`);
    insertPredicates.push(`${iri} <http://darklight.ai/ns/common#object_type> "required-asset"`); 
    insertPredicates.push(`${iri} <http://darklight.ai/ns/common#created> "${timestamp}"^^xsd:dateTime`);
    insertPredicates.push(`${iri} <http://darklight.ai/ns/common#modified> "${timestamp}"^^xsd:dateTime `);
    insertPredicates.push(`${iri} <http://csrc.nist.gov/ns/oscal/common#name> "${reqAsset.name}"`);
    insertPredicates.push(`${iri} <http://csrc.nist.gov/ns/oscal/common#description> "${reqAsset.description}"`);
    graphs.push(`
  GRAPH ${iri} {
    ${insertPredicates.join(".\n        ")}
  }
    `)
  })
  const query = `
  INSERT DATA {
    ${graphs.join("\n")}
  }`;
  return {reqAssetIris, query};
}
export const selectRequiredAssetQuery = (id, select) => {
  return selectRequiredAssetByIriQuery(`http://csrc.nist.gov/ns/oscal/assessment/common#RequiredAsset-${id}`, select);
}
export const selectRequiredAssetByIriQuery = (iri, select) => {
  if (!iri.startsWith('<')) iri = `<${iri}>`;
  if (select === undefined || select === null) select = Object.keys(requiredAssetPredicateMap);
  const { selectionClause, predicates } = buildSelectVariables(requiredAssetPredicateMap, select);
  return `
  SELECT ?iri ${selectionClause}
  FROM <tag:stardog:api:context:local>
  WHERE {
    BIND(${iri} AS ?iri)
    ?iri a <http://csrc.nist.gov/ns/oscal/assessment/common#RequiredAsset> .
    ${predicates}
  }
  `
}
export const selectAllRequiredAssets = (select, args) => {
  if (select === undefined || select === null) select = Object.keys(requiredAssetPredicateMap);
  if (!select.includes('id')) select.push('id');

  if (args !== undefined ) {
    if ( args.filters !== undefined ) {
      for( const filter of args.filters) {
        if (!select.includes(filter.key)) select.push( filter.key );
      }
    }
    
    // add value of orderedBy's key to cause special predicates to be included
    if ( args.orderedBy !== undefined ) {
      if (!select.includes(args.orderedBy)) select.push(args.orderedBy);
    }
  }

  const { selectionClause, predicates } = buildSelectVariables(requiredAssetPredicateMap, select);
  return `
  SELECT DISTINCT ?iri ${selectionClause} 
  FROM <tag:stardog:api:context:local>
  WHERE {
    ?iri a <http://csrc.nist.gov/ns/oscal/assessment/common#RequiredAsset> . 
    ${predicates}
  }
  `
}
export const deleteRequiredAssetQuery = (id) => {
  const iri = `http://csrc.nist.gov/ns/oscal/assessment/common#RequiredAsset-${id}`;
  return deleteRequiredAssetByIriQuery(iri);
}
export const deleteRequiredAssetByIriQuery = (iri) => {
  return `
  DELETE {
    GRAPH <${iri}> {
      ?iri ?p ?o
    }
  } WHERE {
    GRAPH <${iri}> {
      ?iri a <http://csrc.nist.gov/ns/oscal/assessment/common#RequiredAsset> .
      ?iri ?p ?o
    }
  }
  `
}
export const attachToRequiredAssetQuery = (id, field, itemIris) => {
  const iri = `<http://csrc.nist.gov/ns/oscal/assessment/common#RequiredAsset-${id}>`;
  if (!requiredAssetPredicateMap.hasOwnProperty(field)) return null;
  const predicate = requiredAssetPredicateMap[field].predicate;
  let statements;
  if (Array.isArray(itemIris)) {
    statements = itemIris
      .map((itemIri) => `${iri} ${predicate} ${itemIri}`)
      .join(".\n        ")
    }
  else {
    if (!itemIris.startsWith('<')) itemIris = `<${itemIris}>`;
    statements = `${iri} ${predicate} ${itemIris}`;
  }
  return `
  INSERT DATA {
    GRAPH ${iri} {
      ${statements}
    }
  }
  `
}
export const detachFromRequiredAssetQuery = (id, field, itemIris) => {
  const iri = `<http://csrc.nist.gov/ns/oscal/assessment/common#RequiredAsset-${id}>`;
  if (!requiredAssetPredicateMap.hasOwnProperty(field)) return null;
  const predicate = requiredAssetPredicateMap[field].predicate;
  let statements;
  if (Array.isArray(itemIris)) {
    statements = itemIris
      .map((itemIri) => `${iri} ${predicate} ${itemIri}`)
      .join(".\n        ")
    }
  else {
    if (!itemIris.startsWith('<')) itemIris = `<${itemIris}>`;
    statements = `${iri} ${predicate} ${itemIris}`;
  }
  return `
  DELETE DATA {
    GRAPH ${iri} {
      ${statements}
    }
  }
  `
}

// Risk support functions
export const insertRiskQuery = (propValues) => {
  const id_material = {
    ...(propValues.name && {"name": propValues.name}),
  } ;
  const id = generateId( id_material, OSCAL_NS );
  const timestamp = new Date().toISOString();

  // escape any special characters (e.g., newline)
  if (propValues.description !== undefined) {
    if (propValues.description.includes('\n')) propValues.description = propValues.description.replace(/\n/g, '\\n');
    if (propValues.description.includes('\"')) propValues.description = propValues.description.replace(/\"/g, '\\"');
    if (propValues.description.includes("\'")) propValues.description = propValues.description.replace(/\'/g, "\\'");
  }
  if (propValues.statement !== undefined) {
    if (propValues.statement.includes('\n')) propValues.statement = propValues.statement.replace(/\n/g, '\\n');
    if (propValues.statement.includes('\"')) propValues.statement = propValues.statement.replace(/\"/g, '\\"');
    if (propValues.statement.includes("\'")) propValues.statement = propValues.statement.replace(/\'/g, "\\'");
  }

  const iri = `<http://csrc.nist.gov/ns/oscal/assessment/common#Risk-${id}>`;
  const insertPredicates = Object.entries(propValues)
      .filter((propPair) => riskPredicateMap.hasOwnProperty(propPair[0]))
      .map((propPair) => riskPredicateMap[propPair[0]].binding(iri, propPair[1]))
      .join('. \n      ');
  const query = `
  INSERT DATA {
    GRAPH ${iri} {
      ${iri} a <http://csrc.nist.gov/ns/oscal/assessment/common#Risk> .
      ${iri} a <http://csrc.nist.gov/ns/oscal/common#Object> .
      ${iri} a <http://darklight.ai/ns/common#Object> .
      ${iri} <http://darklight.ai/ns/common#id> "${id}".
      ${iri} <http://darklight.ai/ns/common#object_type> "risk" . 
      ${iri} <http://darklight.ai/ns/common#created> "${timestamp}"^^xsd:dateTime . 
      ${iri} <http://darklight.ai/ns/common#modified> "${timestamp}"^^xsd:dateTime . 
      ${insertPredicates}
    }
  }
  `;
  return {iri, id, query}  
}
export const selectRiskQuery = (id, select) => {
  return selectRiskByIriQuery(`http://csrc.nist.gov/ns/oscal/assessment/common#Risk-${id}`, select);
}
export const selectRiskByIriQuery = (iri, select) => {
  const insertSelections = [], groupByClause = [];
  let occurrences = '', occurrenceQuery = '';

  if (!iri.startsWith('<')) iri = `<${iri}>`;
  if (select === undefined || select === null) select = Object.keys(riskPredicateMap);
  if (!select.includes('id')) select.push('id');

  // extension properties
  if (select.includes('props')) {
    if (!select.includes('risk_level')) select.push('risk_level');
    if (!select.includes('false_positive')) select.push('false_positive');
    if (!select.includes('accepted')) select.push('accepted');
    if (!select.includes('risk_adjusted')) select.push('risk_adjusted');
    if (!select.includes('priority')) select.push('priority')
    if (!select.includes('occurrences')) select.push('occurrences');
  }
  

  // fetch the uuid of each related_observation and related_risk as these are commonly used
  if (select.includes('related_observations')) select.push('related_observation_ids');

  // Update select to collect additional predicates if looking to calculate risk level
  if (select.includes('risk_level')) {
    if (!select.includes('cvss2_base_score')) select.push('cvss2_base_score');
    if (!select.includes('cvss2_temporal_score')) select.push('cvss2_temporal_score');
    if (!select.includes('cvss3_base_score')) select.push('cvss3_base_score');
    if (!select.includes('cvss3_temporal_score')) select.push('cvss3_temporal_score');
    if (!select.includes('available_exploit')) select.push('available_exploit');
    if (!select.includes('exploitability_ease')) select.push('exploitability_ease');
  }
  // Update select to collect additional predicates if looking for response type
  if (select.includes('response_type')|| select.includes('lifecycle')) {
    if (!select.includes('remediation_type')) select.push('remediation_type');
    if (!select.includes('remediation_lifecycle')) select.push('remediation_lifecycle')
    if (!select.includes('remediation_timestamp')) select.push('remediation_timestamp')
  }
  if (select.includes('first_seen') || select.includes('last_seen')) {
    if(!select.includes('collected')) select.push('collected');
  }

  // build selectionClause and predicate list
  let { selectionClause, predicates } = buildSelectVariables(riskPredicateMap, select);
  
  // remove any select items pushed from selectionClause to reduce what is not returned
  if (select.includes('risk_level')) {
    selectionClause = selectionClause.replace('?cvss2_base_score','');
    selectionClause = selectionClause.replace('?cvss2_temporal_score','');
    selectionClause = selectionClause.replace('?cvss3_base_score','');
    selectionClause = selectionClause.replace('?cvss3_temporal_score','');
    selectionClause = selectionClause.replace('?available_exploit','');
    selectionClause = selectionClause.replace('?exploitability_ease','');
  }
  if (select.includes('response_type')|| select.includes('response_lifecycle')) {
    selectionClause = selectionClause.replace('?remediation_type','');
    selectionClause = selectionClause.replace('?remediation_lifecycle','')
    selectionClause = selectionClause.replace('?remediation_timestamp','')
  }
  if (select.includes('first_seen') || select.includes('last_seen')) {
    selectionClause = selectionClause.replace('?collected','');
  }

  // Populate the insertSelections that compute results
  if (select.includes('risk_level')) {
    insertSelections.push(`(MAX(?cvss2_base_score) AS ?cvssV2Base_score) (MAX(?cvss2_temporal_score) as ?cvssV2Temporal_score)`);
    insertSelections.push(`(MAX(?cvss3_base_score) AS ?cvssV3Base_score) (MAX(?cvss3_temporal_score) as ?cvssV3Temporal_score)`);
    insertSelections.push(`(GROUP_CONCAT(DISTINCT ?available_exploit;SEPARATOR=",") as ?available_exploit_values)`);
    insertSelections.push(`(GROUP_CONCAT(DISTINCT ?exploitability_ease;SEPARATOR=",") as ?exploitability_ease_values)`);
  }
  if (select.includes('response_type') || select.includes('response_lifecycle')) {
    insertSelections.push(`(GROUP_CONCAT(DISTINCT ?remediation_type;SEPARATOR=",") AS ?remediation_type_values)`);
    insertSelections.push(`(GROUP_CONCAT(DISTINCT ?remediation_lifecycle;SEPARATOR=",") AS ?remediation_lifecycle_values)`);
    insertSelections.push(`(GROUP_CONCAT(DISTINCT ?remediation_timestamp;SEPARATOR=",") AS ?remediation_timestamp_values)`);
  }
  if (select.includes('first_seen') || select.includes('last_seen')) {
    insertSelections.push(`(MIN(?collected) AS ?first_seen) (MAX(?collected) as ?last_seen)`);
  }
  if (select.includes('occurrences')) {
    occurrences = '?occurrences';
    occurrenceQuery = `
      OPTIONAL {
        {
          SELECT DISTINCT ?iri (COUNT(DISTINCT ?subjects) AS ?count)
          WHERE {
            ?iri <http://csrc.nist.gov/ns/oscal/assessment/common#related_observations> ?related_observations .
            ?related_observations <http://csrc.nist.gov/ns/oscal/assessment/common#subjects> ?subjects .
            ?subjects <http://darklight.ai/ns/oscal/assessment/common#subject_context> "target" .
          }
          GROUP BY ?iri
        }
      }
      BIND(IF(!BOUND(?count), 0, ?count) AS ?occurrences)
  `;
  }

  // build "GROUP BY" clause if performing counting or consolidation
  if (select.includes('risk_level') || select.includes('response_type') || 
      select.includes('response_lifecycle') || select.includes('occurrences')) {
      groupByClause.push(`GROUP BY ?iri ${selectionClause.trim()} ${occurrences}`); 
  }
  
  return `
  SELECT DISTINCT ?iri ${selectionClause.trim()} ${occurrences}
  ${insertSelections.join("\n")}
  FROM <tag:stardog:api:context:local>
  WHERE {
    BIND(${iri} AS ?iri)
    ?iri a <http://csrc.nist.gov/ns/oscal/assessment/common#Risk> .
    ${predicates}
    ${occurrenceQuery}
  }
  ${groupByClause.join("\n")}
  `
}
export const selectAllRisks = (select, args, parent) => {
  const insertSelections = [], groupByClause = [];
  let occurrences = '', occurrenceQuery = '', constraintClause = '';
  if (select === undefined || select === null) select = Object.keys(riskPredicateMap);
  if (!select.includes('id')) select.push('id');

  // extension properties
  if (select.includes('props')) {
    if (!select.includes('risk_level')) select.push('risk_level');
    if (!select.includes('false_positive')) select.push('false_positive');
    if (!select.includes('accepted')) select.push('accepted');
    if (!select.includes('risk_adjusted')) select.push('risk_adjusted');
    if (!select.includes('priority')) select.push('priority');
    if (!select.includes('occurrences')) select.push('occurrences');
  }
  
  // fetch the uuid of each related_observation and related_risk as these are commonly used
  if (select.includes('related_observations')) select.push('related_observation_ids');

  // Update select to impact what predicates get retrieved if looking to calculate risk level
  if (select.includes('risk_level')) {
    if (!select.includes('cvss2_base_score')) select.push('cvss2_base_score');
    if (!select.includes('cvss2_temporal_score')) select.push('cvss2_temporal_score');
    if (!select.includes('cvss3_base_score')) select.push('cvss3_base_score');
    if (!select.includes('cvss3_temporal_score')) select.push('cvss3_temporal_score');
    if (!select.includes('available_exploit')) select.push('available_exploit');
    if (!select.includes('exploitability_ease')) select.push('exploitability_ease');
  }
  // Update select to collect additional predicates if looking for response type
  if (select.includes('response_type')|| select.includes('lifecycle')) {
    if (!select.includes('remediation_type')) select.push('remediation_type');
    if (!select.includes('remediation_lifecycle')) select.push('remediation_lifecycle');
    if (!select.includes('remediation_timestamp')) select.push('remediation_timestamp');
  }
  if (select.includes('first_seen') || select.includes('last_seen')) {
    if(!select.includes('collected')) select.push('collected');
  }

  if (args !== undefined ) {
    if ( args.filters !== undefined ) {
      for( const filter of args.filters) {
        if (filter === undefined || filter === null) continue;
        if (!select.includes(filter.key)) select.push( filter.key );
      }
    }
    
    // add value of orderedBy's key to cause special predicates to be included
    if ( args.orderedBy !== undefined ) {
      if (!select.includes(args.orderedBy)) select.push(args.orderedBy);
    }
  }

  // build selectionClause and predicate list
  let { selectionClause, predicates } = buildSelectVariables(riskPredicateMap, select);

  // add constraint clause to limit to those that are referenced by the specified POAM
  if (parent !== undefined && parent.iri !== undefined) {
    let classTypeIri, predicate;
    if (parent.entity_type === 'poam') {
      classTypeIri = '<http://csrc.nist.gov/ns/oscal/common#POAM>';
      predicate = '<http://csrc.nist.gov/ns/oscal/poam#risks>';
    }
    if (parent.entity_type === 'poam-item') {
      classTypeIri = '<http://csrc.nist.gov/ns/oscal/poam#Item>';
      predicate = '<http://csrc.nist.gov/ns/oscal/assessment/common#related_risks>';
    }
    if (parent.entity_type === 'result') {
      classTypeIri = '<http://csrc.nist.gov/ns/oscal/assessment-results#Result>';
      predicate = '<http://csrc.nist.gov/ns/oscal/assessment/common#risks>';
    }
    if (parent.entity_type === 'finding') {
      classTypeIri = '<http://csrc.nist.gov/ns/oscal/assessment-results#Finding>'
      predicate = '<http://csrc.nist.gov/ns/oscal/assessment/common#related_risks>';
    }
    // define a constraint to limit retrieval to only those referenced by the parent
    constraintClause = `
    {
      SELECT DISTINCT ?iri
      WHERE {
          <${parent.iri}> a ${classTypeIri} ;
            ${predicate} ?iri .
      }
    }
    `;
  }

  // remove any select items pushed from selectionClause to reduce what is not returned
  if (select.includes('risk_level')) {
    selectionClause = selectionClause.replace('?cvss2_base_score','');
    selectionClause = selectionClause.replace('?cvss2_temporal_score','');
    selectionClause = selectionClause.replace('?cvss3_base_score','');
    selectionClause = selectionClause.replace('?cvss3_temporal_score','');
    selectionClause = selectionClause.replace('?available_exploit','');
    selectionClause = selectionClause.replace('?exploitability_ease','');
  }
  if (select.includes('response_type') || select.includes('response_lifecycle')) {
    selectionClause = selectionClause.replace('?remediation_type','');
    selectionClause = selectionClause.replace('?remediation_lifecycle','')
    selectionClause = selectionClause.replace('?remediation_timestamp','')    
  }
  if (select.includes('first_seen') || select.includes('last_seen')) {
    selectionClause = selectionClause.replace('?collected','');
  }

  // Populate the insertSelections that compute results
  if (select.includes('risk_level')) {
    insertSelections.push(`(MAX(?cvss2_base_score) AS ?cvssV2Base_score) (MAX(?cvss2_temporal_score) as ?cvssV2Temporal_score)`);
    insertSelections.push(`(MAX(?cvss3_base_score) AS ?cvssV3Base_score) (MAX(?cvss3_temporal_score) as ?cvssV3Temporal_score)`);
    insertSelections.push(`(GROUP_CONCAT(DISTINCT ?available_exploit;SEPARATOR=",") as ?available_exploit_values)`);
    insertSelections.push(`(GROUP_CONCAT(DISTINCT ?exploitability_ease;SEPARATOR=",") as ?exploitability_ease_values)`);
  }
  if (select.includes('response_type') || select.includes('response_lifecycle')) {
    insertSelections.push(`(GROUP_CONCAT(DISTINCT ?remediation_type;SEPARATOR=",") AS ?remediation_type_values)`);
    insertSelections.push(`(GROUP_CONCAT(DISTINCT ?remediation_lifecycle;SEPARATOR=",") AS ?remediation_lifecycle_values)`);
    insertSelections.push(`(GROUP_CONCAT(DISTINCT ?remediation_timestamp;SEPARATOR=",") AS ?remediation_timestamp_values)`);
  }
  if (select.includes('first_seen') || select.includes('last_seen')) {
    insertSelections.push(`(MIN(?collected) AS ?first_seen) (MAX(?collected) as ?last_seen)`);
  }
  if (select.includes('occurrences')) {
    occurrences = '?occurrences';
    occurrenceQuery = `
      OPTIONAL {
        {
          SELECT DISTINCT ?iri (COUNT(DISTINCT ?subjects) AS ?count)
          WHERE {
            ?iri <http://csrc.nist.gov/ns/oscal/assessment/common#related_observations> ?related_observations .
            ?related_observations <http://csrc.nist.gov/ns/oscal/assessment/common#subjects> ?subjects .
            ?subjects <http://darklight.ai/ns/oscal/assessment/common#subject_context> "target" .
      }
          GROUP BY ?iri
        }
      }
      BIND(IF(!BOUND(?count), 0, ?count) AS ?occurrences)
  `;
  }

  // build "GROUP BY" clause if performing counting or consolidation
  if (select.includes('risk_level') || select.includes('response_type') || 
      select.includes('response_lifecycle') || select.includes('occurrences')) {
      groupByClause.push(`GROUP BY ?iri ${selectionClause.trim()} ${occurrences}`); 
  }

  return `
  SELECT DISTINCT ?iri ${selectionClause.trim()} ${occurrences}
  ${insertSelections.join("\n")}
  FROM <tag:stardog:api:context:local>
  WHERE {
    ?iri a <http://csrc.nist.gov/ns/oscal/assessment/common#Risk> . 
    ${predicates}
    ${occurrenceQuery}
    ${constraintClause}
  }
  ${groupByClause.join("\n")}
  `
}
export const deleteRiskQuery = (id) => {
  const iri = `http://csrc.nist.gov/ns/oscal/assessment/common#Risk-${id}`;
  return deleteRiskByIriQuery(iri);
}
export const deleteRiskByIriQuery = (iri) => {
  return `
  DELETE {
    GRAPH <${iri}> {
      ?iri ?p ?o
    }
  } WHERE {
    GRAPH <${iri}> {
      ?iri a <http://csrc.nist.gov/ns/oscal/assessment/common#Risk> .
      ?iri ?p ?o
    }
  }
  `
}
export const attachToRiskQuery = (id, field, itemIris) => {
  const iri = `<http://csrc.nist.gov/ns/oscal/assessment/common#Risk-${id}>`;
  if (!riskPredicateMap.hasOwnProperty(field)) return null;
  const predicate = riskPredicateMap[field].predicate;
  let statements;
  if (Array.isArray(itemIris)) {
    statements = itemIris
      .map((itemIri) => `${iri} ${predicate} ${itemIri}`)
      .join(".\n        ")
    }
  else {
    if (!itemIris.startsWith('<')) itemIris = `<${itemIris}>`;
    statements = `${iri} ${predicate} ${itemIris}`;
  }
  return `
  INSERT DATA {
    GRAPH ${iri} {
      ${statements}
    }
  }
  `
}
export const detachFromRiskQuery = (id, field, itemIris) => {
  const iri = `<http://csrc.nist.gov/ns/oscal/assessment/common#Risk-${id}>`;
  if (!riskPredicateMap.hasOwnProperty(field)) return null;
  const predicate = riskPredicateMap[field].predicate;
  let statements;
  if (Array.isArray(itemIris)) {
    statements = itemIris
      .map((itemIri) => `${iri} ${predicate} ${itemIri}`)
      .join(".\n        ")
    }
  else {
    if (!itemIris.startsWith('<')) itemIris = `<${itemIris}>`;
    statements = `${iri} ${predicate} ${itemIris}`;
  }
  return `
  DELETE DATA {
    GRAPH ${iri} {
      ${statements}
    }
  }
  `
}

// Risk Log Entry support functions
export const insertRiskLogEntryQuery = (propValues) => {
  // remove any object types from the list of propValues
  let riskId, responses, authors;
  if (propValues.logged_by !== undefined) {
    authors = propValues.logged_by;
    delete propValues.logged_by;
  }
  if (propValues.related_responses !== undefined) {
    responses = propValues.related_responses;
    delete propValues.responses;
  }
  if (propValues.risk_id !== undefined) {
    riskId = propValues.risk_id;
    delete propValues.risk_id;
  }

  // escape any special characters (e.g., newline)
  if (propValues.description !== undefined) {
    if (propValues.description.includes('\n')) propValues.description = propValues.description.replace(/\n/g, '\\n');
    if (propValues.description.includes('\"')) propValues.description = propValues.description.replace(/\"/g, '\\"');
    if (propValues.description.includes("\'")) propValues.description = propValues.description.replace(/\'/g, "\\'");
  }

  const id = generateId( );
  const timestamp = new Date().toISOString()
  const iri = `<http://csrc.nist.gov/ns/oscal/assessment/common#RiskLogEntry-${id}>`;
  const insertPredicates = Object.entries(propValues)
      .filter((propPair) => riskLogPredicateMap.hasOwnProperty(propPair[0]))
      .map((propPair) => riskLogPredicateMap[propPair[0]].binding(iri, propPair[1]))
      .join('. \n      ');
  const query = `
  INSERT DATA {
    GRAPH ${iri} {
      ${iri} a <http://csrc.nist.gov/ns/oscal/assessment/common#RiskLogEntry> .
      ${iri} a <http://csrc.nist.gov/ns/oscal/assessment/common#LogEntry> .
      ${iri} a <http://csrc.nist.gov/ns/oscal/common#Object> .
      ${iri} a <http://darklight.ai/ns/common#Object> .
      ${iri} <http://darklight.ai/ns/common#id> "${id}".
      ${iri} <http://darklight.ai/ns/common#object_type> "risk-log-entry" . 
      ${iri} <http://darklight.ai/ns/common#created> "${timestamp}"^^xsd:dateTime . 
      ${iri} <http://darklight.ai/ns/common#modified> "${timestamp}"^^xsd:dateTime . 
      ${insertPredicates}
    }
  }
  `;

  // restore the propValues passed in
  if (authors !== undefined) propValues.logged_by = authors;
  if (responses !== undefined) propValues.related_responses = responses;
  if (riskId !== undefined) propValues.risk_id = riskId;

  return {iri, id, query}  
}
export const selectRiskLogEntryQuery = (id, select) => {
  return selectRiskLogEntryByIriQuery(`http://csrc.nist.gov/ns/oscal/assessment/common#RiskLogEntry-${id}`, select);
}
export const selectRiskLogEntryByIriQuery = (iri, select) => {
  if (!iri.startsWith('<')) iri = `<${iri}>`;
  if (select === undefined || select === null) select = Object.keys(riskLogPredicateMap);
  const { selectionClause, predicates } = buildSelectVariables(riskLogPredicateMap, select);
  return `
  SELECT ?iri ${selectionClause}
  FROM <tag:stardog:api:context:local>
  WHERE {
    BIND(${iri} AS ?iri)
    ?iri a <http://csrc.nist.gov/ns/oscal/assessment/common#RiskLogEntry> .
    ${predicates}
  }
  `
}
export const selectAllRiskLogEntries = (select, args, parent) => {
  let constraintClause = '';
  if (select === undefined || select === null) select = Object.keys(riskLogPredicateMap);
  if (!select.includes('id')) select.push('id');

  if (args !== undefined ) {
    if ( args.filters !== undefined ) {
      for( const filter of args.filters) {
        if (!select.includes(filter.key)) select.push( filter.key );
      }
    }
    
    // add value of orderedBy's key to cause special predicates to be included
    if ( args.orderedBy !== undefined ) {
      if (!select.includes(args.orderedBy)) select.push(args.orderedBy);
    }
  }

  const { selectionClause, predicates } = buildSelectVariables(riskLogPredicateMap, select);
  // add constraint clause to limit to those that are referenced by the specified POAM
  if (parent !== undefined && parent.iri !== undefined) {
    // define a constraint to limit retrieval to only those referenced by the parent
    constraintClause = `
    {
      SELECT DISTINCT ?iri
      WHERE {
          <${parent.iri}> a <http://csrc.nist.gov/ns/oscal/assessment/common#Risk> ;
          <http://csrc.nist.gov/ns/oscal/assessment/common#risk_log> ?iri .
      }
    }
    `;
  }

  return `
  SELECT DISTINCT ?iri ${selectionClause} 
  FROM <tag:stardog:api:context:local>
  WHERE {
    ?iri a <http://csrc.nist.gov/ns/oscal/assessment/common#RiskLogEntry> . 
    ${predicates}
    ${constraintClause}
  }
  `
}
export const deleteRiskLogEntryQuery = (id) => {
  const iri = `http://csrc.nist.gov/ns/oscal/assessment/common#RiskLogEntry-${id}`;
  return deleteRiskLogEntryByIriQuery(iri);
}
export const deleteRiskLogEntryByIriQuery = (iri) => {
  return `
  DELETE {
    GRAPH <${iri}> {
      ?iri ?p ?o
    }
  } WHERE {
    GRAPH <${iri}> {
      ?iri a <http://csrc.nist.gov/ns/oscal/assessment/common#RiskLogEntry> .
      ?iri ?p ?o
    }
  }
  `
}
export const attachToRiskLogEntryQuery = (id, field, itemIris) => {
  const iri = `<http://csrc.nist.gov/ns/oscal/assessment/common#RiskLogEntry-${id}>`;
  if (!riskLogPredicateMap.hasOwnProperty(field)) return null;
  const predicate = riskLogPredicateMap[field].predicate;
  let statements;
  if (Array.isArray(itemIris)) {
    statements = itemIris
      .map((itemIri) => `${iri} ${predicate} ${itemIri}`)
      .join(".\n        ")
    }
  else {
    if (!itemIris.startsWith('<')) itemIris = `<${itemIris}>`;
    statements = `${iri} ${predicate} ${itemIris}`;
  }
  return `
  INSERT DATA {
    GRAPH ${iri} {
      ${statements}
    }
  }
  `
}
export const detachFromRiskLogEntryQuery = (id, field, itemIris) => {
  const iri = `<http://csrc.nist.gov/ns/oscal/assessment/common#RiskLogEntry-${id}>`;
  if (!riskLogPredicateMap.hasOwnProperty(field)) return null;
  const predicate = riskLogPredicateMap[field].predicate;
  let statements;
  if (Array.isArray(itemIris)) {
    statements = itemIris
      .map((itemIri) => `${iri} ${predicate} ${itemIri}`)
      .join(".\n        ")
    }
  else {
    if (!itemIris.startsWith('<')) itemIris = `<${itemIris}>`;
    statements = `${iri} ${predicate} ${itemIris}`;
  }
  return `
  DELETE DATA {
    GRAPH ${iri} {
      ${statements}
    }
  }
  `
}

// Risk Response support functions
export const insertRiskResponseQuery = (propValues) => {
  // remove any object types from the list of propValues
  let origins, assets, tasks, riskId;
  if (propValues.origins !== undefined) {
    origins = propValues.origins;
    delete propValues.origins;
  }
  if (propValues.required_assets !== undefined) {
    assets = propValues.required_assets;
    delete propValues.required_assets;
  }
  if (propValues.tasks !== undefined) {
    tasks = propValues.tasks;
    delete propValues.tasks;
  }
  if (propValues.risk_id !== undefined) {
    riskId = propValues.risk_id;
    delete propValues.risk_id;
  }

  const id_material = {
    ...(origins[0].origin_actors[0].actor_type && {"actor_type": origins[0].origin_actors[0].actor_type}),
    ...(origins[0].origin_actors[0].actor_ref && {"actor_ref": origins[0].origin_actors[0].actor_ref}),
    ...(riskId && {"risk_id": riskId}),
  } ;
  const id = generateId( id_material, OSCAL_NS );

  // escape any special characters (e.g., newline)
  if (propValues.description !== undefined) {
    if (propValues.description.includes('\n')) propValues.description = propValues.description.replace(/\n/g, '\\n');
    if (propValues.description.includes('\"')) propValues.description = propValues.description.replace(/\"/g, '\\"');
    if (propValues.description.includes("\'")) propValues.description = propValues.description.replace(/\'/g, "\\'");
  }
  
  const timestamp = new Date().toISOString()
  const iri = `<http://csrc.nist.gov/ns/oscal/assessment/common#RiskResponse-${id}>`;
  const insertPredicates = Object.entries(propValues)
      .filter((propPair) => riskResponsePredicateMap.hasOwnProperty(propPair[0]))
      .map((propPair) => riskResponsePredicateMap[propPair[0]].binding(iri, propPair[1]))
      .join('. \n      ');
  const query = `
  INSERT DATA {
    GRAPH ${iri} {
      ${iri} a <http://csrc.nist.gov/ns/oscal/assessment/common#RiskResponse> .
      ${iri} a <http://csrc.nist.gov/ns/oscal/common#Object> .
      ${iri} a <http://darklight.ai/ns/common#Object> .
      ${iri} <http://darklight.ai/ns/common#id> "${id}".
      ${iri} <http://darklight.ai/ns/common#object_type> "risk-response" . 
      ${iri} <http://darklight.ai/ns/common#created> "${timestamp}"^^xsd:dateTime . 
      ${iri} <http://darklight.ai/ns/common#modified> "${timestamp}"^^xsd:dateTime . 
      ${insertPredicates}
    }
  }
  `;

  // restore the propValues passed in
  if (origins !== undefined) propValues.origins = origins;
  if (assets !== undefined) propValues.required_assets = assets;
  if (tasks !== undefined) propValues.tasks = tasks;
  if (riskId !== undefined) propValues.risk_id = riskId;
  
  return {iri, id, query}  
}
export const selectRiskResponseQuery = (id, select) => {
  return selectRiskResponseByIriQuery(`http://csrc.nist.gov/ns/oscal/assessment/common#RiskResponse-${id}`, select);
}
export const selectRiskResponseByIriQuery = (iri, select) => {
  if (!iri.startsWith('<')) iri = `<${iri}>`;
  if (select === undefined || select === null) select = Object.keys(riskResponsePredicateMap);

  // extension properties
  if (select.includes('props')) {
    if (!select.includes('response_type')) select.push('response_type');
  }
  
  const { selectionClause, predicates } = buildSelectVariables(riskResponsePredicateMap, select);
  return `
  SELECT ?iri ${selectionClause}
  FROM <tag:stardog:api:context:local>
  WHERE {
    BIND(${iri} AS ?iri)
    ?iri a <http://csrc.nist.gov/ns/oscal/assessment/common#RiskResponse> .
    ${predicates}
  }
  `
}
export const selectAllRiskResponses = (select, args) => {
  if (select === undefined || select === null) select = Object.keys(riskResponsePredicateMap);
  if (!select.includes('id')) select.push('id');

  // extension properties
  if (select.includes('props')) {
    if (!select.includes('response_type')) select.push('response_type');
  }
  
  if (args !== undefined ) {
    if ( args.filters !== undefined ) {
      for( const filter of args.filters) {
        if (!select.includes(filter.key)) select.push( filter.key );
      }
    }
    
    // add value of orderedBy's key to cause special predicates to be included
    if ( args.orderedBy !== undefined ) {
      if (!select.includes(args.orderedBy)) select.push(args.orderedBy);
    }
  }

  const { selectionClause, predicates } = buildSelectVariables(riskResponsePredicateMap, select);
  return `
  SELECT DISTINCT ?iri ${selectionClause} 
  FROM <tag:stardog:api:context:local>
  WHERE {
    ?iri a <http://csrc.nist.gov/ns/oscal/assessment/common#RiskResponse> . 
    ${predicates}
  }
  `
}
export const deleteRiskResponseQuery = (id) => {
  const iri = `http://csrc.nist.gov/ns/oscal/assessment/common#RiskResponse-${id}`;
  return deleteRiskResponseByIriQuery(iri);
}
export const deleteRiskResponseByIriQuery = (iri) => {
  return `
  DELETE {
    GRAPH <${iri}> {
      ?iri ?p ?o
    }
  } WHERE {
    GRAPH <${iri}> {
      ?iri a <http://csrc.nist.gov/ns/oscal/assessment/common#RiskResponse> .
      ?iri ?p ?o
    }
  }
  `
}
export const attachToRiskResponseQuery = (id, field, itemIris) => {
  const iri = `<http://csrc.nist.gov/ns/oscal/assessment/common#RiskResponse-${id}>`;
  if (!riskResponsePredicateMap.hasOwnProperty(field)) return null;
  const predicate = riskResponsePredicateMap[field].predicate;
  let statements;
  if (Array.isArray(itemIris)) {
    statements = itemIris
      .map((itemIri) => `${iri} ${predicate} ${itemIri}`)
      .join(".\n        ")
    }
  else {
    if (!itemIris.startsWith('<')) itemIris = `<${itemIris}>`;
    statements = `${iri} ${predicate} ${itemIris}`;
  }
  return `
  INSERT DATA {
    GRAPH ${iri} {
      ${statements}
    }
  }
  `
}
export const detachFromRiskResponseQuery = (id, field, itemIris) => {
  const iri = `<http://csrc.nist.gov/ns/oscal/assessment/common#RiskResponse-${id}>`;
  if (!riskResponsePredicateMap.hasOwnProperty(field)) return null;
  const predicate = riskResponsePredicateMap[field].predicate;
  let statements;
  if (Array.isArray(itemIris)) {
    statements = itemIris
      .map((itemIri) => `${iri} ${predicate} ${itemIri}`)
      .join(".\n        ")
    }
  else {
    if (!itemIris.startsWith('<')) itemIris = `<${itemIris}>`;
    statements = `${iri} ${predicate} ${itemIris}`;
  }
  return `
  DELETE DATA {
    GRAPH ${iri} {
      ${statements}
    }
  }
  `
}

// Subject support functions
export const insertSubjectQuery = (propValues) => {
  const id_material = {
    ...(propValues.subject_context && {"subject_context": propValues.subject_context}),
    ...(propValues.subject_ref && {"subject_ref": propValues.subject_ref}),
    ...(propValues.subject_type && {"subject_type": propValues.subject_type}),
  } ;
  const id = generateId( id_material, OSCAL_NS );
  const iri = `<http://csrc.nist.gov/ns/oscal/assessment/common#Subject-${id}>`;
  const insertPredicates = Object.entries(propValues)
      .filter((propPair) => subjectPredicateMap.hasOwnProperty(propPair[0]))
      .map((propPair) => subjectPredicateMap[propPair[0]].binding(iri, propPair[1]))
      .join('. \n      ');
  const query = `
  INSERT DATA {
    GRAPH ${iri} {
      ${iri} a <http://csrc.nist.gov/ns/oscal/assessment/common#Subject> .
      ${iri} a <http://csrc.nist.gov/ns/oscal/common#ComplexDatatype> .
      ${iri} a <http://darklight.ai/ns/common#ComplexDatatype> .
      ${iri} <http://darklight.ai/ns/common#id> "${id}" .
      ${iri} <http://darklight.ai/ns/common#object_type> "subject" . 
      ${insertPredicates}
    }
  }
  `;
  return {iri, id, query}  
}
export const insertSubjectsQuery = (subjects) => {
  const graphs = [], subjectIris = [];
  subjects.forEach((subject) => {
    const id_material = {
      ...(subject.subject_context && {"subject_context": subject.subject_context}),
      ...(subject.subject_ref && {"subject_ref": subject.subject_ref}),
      ...(subject.subject_type && {"subject_type": subject.subject_type}),
    } ;
    if (!subject.subject_ref.startsWith('<')) subject.subject_ref = `<${subject.subject_ref}>`;
    const id = generateId( id_material, OSCAL_NS );
    const insertPredicates = [];
    const iri = `<http://csrc.nist.gov/ns/oscal/assessment/common#Subject-${id}>`;
    subjectIris.push(iri);
    insertPredicates.push(`${iri} a <http://csrc.nist.gov/ns/oscal/assessment/common#Subject>`);
    insertPredicates.push(`${iri} a <http://csrc.nist.gov/ns/oscal/common#ComplexDatatype>`);
    insertPredicates.push(`${iri} a <http://darklight.ai/ns/common#ComplexDatatype>`);
    insertPredicates.push(`${iri} <http://darklight.ai/ns/common#id> "${id}"`);
    insertPredicates.push(`${iri} <http://darklight.ai/ns/common#object_type> "subject"`); 
    if (subject.name != undefined) insertPredicates.push(`${iri} <http://csrc.nist.gov/ns/oscal/common#name> "${subject.name}"`);
    insertPredicates.push(`${iri} <http://csrc.nist.gov/ns/oscal/assessment/common#subject_type> "${subject.subject_type}"`);
    insertPredicates.push(`${iri} <http://csrc.nist.gov/ns/oscal/assessment/common#subject_ref> ${subject.subject_ref}`);
    if (subject.subject_context != undefined) {
      insertPredicates.push(`${iri} <http://darklight.ai/ns/oscal/assessment/common#subject_context> "${subject.subject_context}"`);
    }
    graphs.push(`
  GRAPH ${iri} {
    ${insertPredicates.join(".\n        ")}
  }
    `)
  })
  const query = `
  INSERT DATA {
    ${graphs.join("\n")}
  }`;
  return {subjectIris, query};
}
export const selectSubjectQuery = (id, select) => {
  return selectSubjectByIriQuery(`http://csrc.nist.gov/ns/oscal/assessment/common#Subject-${id}`, select);
}
export const selectSubjectByIriQuery = (iri, select) => {
  if (!iri.startsWith('<')) iri = `<${iri}>`;
  if (select === undefined || select === null) select = Object.keys(subjectPredicateMap);
  const cloneSelect = [...select];
  // defensive code to protect against query not supplying subject type
  if (!select.includes('subject_type')) cloneSelect.push('subject_type');
  // get the references name and version, if name is asked for
  if (!select.push('subject_ref')) select.push('subject_ref');
  if (!select.push('subject_id')) select.push('subject_id');
  if (!select.push('subject_name')) select.push('subject_name');
  if (!select.push('subject_version')) select.push('subject_version');
  if (!select.push('subject_asset_type')) select.push('subject_asset_type');
  if (!select.push('subject_component_type')) select.push('subject_component_type');
  if (!select.push('subject_location_type')) select.push('subject_location_type');
  if (!select.push('subject_party_type')) select.push('subject_party_type');

  const { selectionClause, predicates } = buildSelectVariables(subjectPredicateMap, cloneSelect);
  return `
  SELECT ?iri ${selectionClause}
  FROM <tag:stardog:api:context:local>
  WHERE {
    BIND(${iri} AS ?iri)
    ?iri a <http://csrc.nist.gov/ns/oscal/assessment/common#Subject> .
    ${predicates}
  }
  `
}

export const selectAllSubjects = (select, args, parent) => {
  let constraintClause = '';
  if (select === undefined || select === null) select = Object.keys(subjectPredicateMap);
  if (!select.includes('id')) select.push('id');
  // defensive code to protect against query not supplying subject type
  if (!select.includes('subject_type')) select.push('subject_type');
  // get the references id, name, version to allow easy detection of subject ref
  if (!select.push('subject_ref')) select.push('subject_ref');
  if (!select.push('subject_id')) select.push('subject_id');
  if (!select.push('subject_name')) select.push('subject_name');
  if (!select.push('subject_version')) select.push('subject_version');
  if (!select.push('subject_asset_type')) select.push('subject_asset_type');
  if (!select.push('subject_component_type')) select.push('subject_component_type');
  if (!select.push('subject_location_type')) select.push('subject_location_type');
  if (!select.push('subject_party_type')) select.push('subject_party_type');

  if (args !== undefined ) {
    if ( args.filters !== undefined ) {
      for( const filter of args.filters) {
        if (!select.includes(filter.key)) select.push(filter.key);
      }
    }
    
    // add value of orderedBy's key to cause special predicates to be included
    if ( args.orderedBy !== undefined ) {
      if (!select.includes(args.orderedBy)) select.push(args.orderedBy);
    }
  }

  const { selectionClause, predicates } = buildSelectVariables(subjectPredicateMap, select);
  if (parent !== undefined && parent.iri !== undefined) {
    let classTypeIri, predicate;
    if (parent.entity_type === 'observation') {
      classTypeIri = '<http://csrc.nist.gov/ns/oscal/assessment/common#Observation>';
      predicate = '<http://csrc.nist.gov/ns/oscal/assessment/common#subjects>';
    }
    if (parent.entity_type === 'mitigating-factor') {
      classTypeIri = '<http://csrc.nist.gov/ns/oscal/assessment/common#MitigatingFactor>';
      predicate = '<http://csrc.nist.gov/ns/oscal/assessment/common#subjects>';
    }
    if (parent.entity_type === 'required-asset') {
      classTypeIri = '<http://csrc.nist.gov/ns/oscal/assessment/common#RequiredAsset>';
      predicate = '<http://csrc.nist.gov/ns/oscal/assessment/common#subjects>';
    }
    // define a constraint to limit retrieval to only those referenced by the parent
    constraintClause = `
    {
      SELECT DISTINCT ?iri
      WHERE {
          <${parent.iri}> a ${classTypeIri} ;
            ${predicate} ?iri .
      }
    }
    `;
  }

  return `
  SELECT DISTINCT ?iri ${selectionClause} 
  FROM <tag:stardog:api:context:local>
  WHERE {
    ?iri a <http://csrc.nist.gov/ns/oscal/assessment/common#Subject> . 
    ${predicates}
    ${constraintClause}
  }
  `
}
export const deleteSubjectQuery = (id) => {
  const iri = `http://csrc.nist.gov/ns/oscal/assessment/common#Subject-${id}`;
  return deleteSubjectByIriQuery(iri);
}
export const deleteSubjectByIriQuery = (iri) => {
  return `
  DELETE {
    GRAPH <${iri}> {
      ?iri ?p ?o
    }
  } WHERE {
    GRAPH <${iri}> {
      ?iri a <http://csrc.nist.gov/ns/oscal/assessment/common#Subject> .
      ?iri ?p ?o
    }
  }`
}
export const attachToSubjectQuery = (id, field, itemIris) => {
  const iri = `<http://csrc.nist.gov/ns/oscal/assessment/common#Subject-${id}>`;
  if (!subjectPredicateMap.hasOwnProperty(field)) return null;
  const predicate = subjectPredicateMap[field].predicate;
  let statements;
  if (Array.isArray(itemIris)) {
    statements = itemIris
      .map((itemIri) => `${iri} ${predicate} ${itemIri}`)
      .join(".\n        ")
    }
  else {
    if (!itemIris.startsWith('<')) itemIris = `<${itemIris}>`;
    statements = `${iri} ${predicate} ${itemIris}`;
  }
  return `
  INSERT DATA {
    GRAPH ${iri} {
      ${statements}
    }
  }
  `
}
export const detachFromSubjectQuery = (id, field, itemIris) => {
  const iri = `<http://csrc.nist.gov/ns/oscal/assessment/common#Subject-${id}>`;
  if (!subjectPredicateMap.hasOwnProperty(field)) return null;
  const predicate = subjectPredicateMap[field].predicate;
  let statements;
  if (Array.isArray(itemIris)) {
    statements = itemIris
      .map((itemIri) => `${iri} ${predicate} ${itemIri}`)
      .join(".\n        ")
    }
  else {
    if (!itemIris.startsWith('<')) itemIris = `<${itemIris}>`;
    statements = `${iri} ${predicate} ${itemIris}`;
  }
  return `
  DELETE DATA {
    GRAPH ${iri} {
      ${statements}
    }
  }
  `
}

// Oscal Task support functions
export const insertOscalTaskQuery = (propValues) => {
  const id_material = {
    ...(propValues.name && {"name": propValues.name}),
    ...(propValues.task_type && {"task_type": propValues.task_type}),
  } ;
  const id = generateId( id_material, OSCAL_NS );
  const timestamp = new Date().toISOString();

  // escape any special characters (e.g., newline)
  if (propValues.description !== undefined) {
    if (propValues.description.includes('\n')) propValues.description = propValues.description.replace(/\n/g, '\\n');
    if (propValues.description.includes('\"')) propValues.description = propValues.description.replace(/\"/g, '\\"');
    if (propValues.description.includes("\'")) propValues.description = propValues.description.replace(/\'/g, "\\'");
  }

  const iri = `<http://csrc.nist.gov/ns/oscal/assessment/common#Task-${id}>`;
  const insertPredicates = Object.entries(propValues)
      .filter((propPair) => oscalTaskPredicateMap.hasOwnProperty(propPair[0]))
      .map((propPair) => oscalTaskPredicateMap[propPair[0]].binding(iri, propPair[1]))
      .join('. \n      ');
  const query = `
  INSERT DATA {
    GRAPH ${iri} {
      ${iri} a <http://csrc.nist.gov/ns/oscal/assessment/common#Task> .
      ${iri} a <http://csrc.nist.gov/ns/oscal/common#Object> .
      ${iri} a <http://darklight.ai/ns/common#Object> .
      ${iri} <http://darklight.ai/ns/common#id> "${id}".
      ${iri} <http://darklight.ai/ns/common#object_type> "oscal-task" . 
      ${iri} <http://darklight.ai/ns/common#created> "${timestamp}"^^xsd:dateTime . 
      ${iri} <http://darklight.ai/ns/common#modified> "${timestamp}"^^xsd:dateTime . 
      ${insertPredicates}
    }
  }
  `;
  return {iri, id, query}  
}
export const selectOscalTaskQuery = (id, select) => {
  return selectOscalTaskByIriQuery(`http://csrc.nist.gov/ns/oscal/assessment/common#Task-${id}`, select);
}
export const selectOscalTaskByIriQuery = (iri, select) => {
  if (!iri.startsWith('<')) iri = `<${iri}>`;
  if (select === undefined || select === null) select = Object.keys(oscalTaskPredicateMap);
  if (!select.includes('id')) select.push('id');
  if (select.includes('timing')) {
    select.push('on_date');
    select.push('start_date');
    select.push('end_date');
    select.push('frequency_period');
    select.push('frequency_unit')
  }

  const { selectionClause, predicates } = buildSelectVariables(oscalTaskPredicateMap, select);
  return `
  SELECT ?iri ${selectionClause}
  FROM <tag:stardog:api:context:local>
  WHERE {
    BIND(${iri} AS ?iri)
    ?iri a <http://csrc.nist.gov/ns/oscal/assessment/common#Task> .
    ${predicates}
  }
  `
}
export const selectAllOscalTasks = (select, args) => {
  if (select === undefined || select === null) select = Object.keys(oscalTaskPredicateMap);
  if (!select.includes('id')) select.push('id');

  if (select.includes('timing')) {
    select.push('on_date');
    select.push('start_date');
    select.push('end_date');
    select.push('frequency_period');
    select.push('frequency_unit')
  }

  if (args !== undefined ) {
    if ( args.filters !== undefined ) {
      for( const filter of args.filters) {
        if (!select.includes(filter.key)) select.push( filter.key );
      }
    }
    
    // add value of orderedBy's key to cause special predicates to be included
    if ( args.orderedBy !== undefined ) {
      if (!select.includes(args.orderedBy)) select.push(args.orderedBy);
    }
  }

  const { selectionClause, predicates } = buildSelectVariables(oscalTaskPredicateMap, select);
  return `
  SELECT DISTINCT ?iri ${selectionClause} 
  FROM <tag:stardog:api:context:local>
  WHERE {
    ?iri a <http://csrc.nist.gov/ns/oscal/assessment/common#Task> . 
    ${predicates}
  }
  `
}
export const deleteOscalTaskQuery = (id) => {
  const iri = `http://csrc.nist.gov/ns/oscal/assessment/common#Task-${id}`;
  return deleteOscalTaskByIriQuery(iri);
}
export const deleteOscalTaskByIriQuery = (iri) => {
  return `
  DELETE {
    GRAPH <${iri}> {
      ?iri ?p ?o
    }
  } WHERE {
    GRAPH <${iri}> {
      ?iri a <http://csrc.nist.gov/ns/oscal/assessment/common#Task> .
      ?iri ?p ?o
    }
  }
  `
}
export const attachToOscalTaskQuery = (id, field, itemIris) => {
  const iri = `<http://csrc.nist.gov/ns/oscal/assessment/common#Task-${id}>`;
  if (!oscalTaskPredicateMap.hasOwnProperty(field)) return null;
  const predicate = oscalTaskPredicateMap[field].predicate;
  let statements;
  if (Array.isArray(itemIris)) {
    statements = itemIris
      .map((itemIri) => `${iri} ${predicate} ${itemIri}`)
      .join(".\n        ")
    }
  else {
    if (!itemIris.startsWith('<')) itemIris = `<${itemIris}>`;
    statements = `${iri} ${predicate} ${itemIris}`;
  }
  return `
  INSERT DATA {
    GRAPH ${iri} {
      ${statements}
    }
  }
  `
}
export const detachFromOscalTaskQuery = (id, field, itemIris) => {
  const iri = `<http://csrc.nist.gov/ns/oscal/assessment/common#Task-${id}>`;
  if (!oscalTaskPredicateMap.hasOwnProperty(field)) return null;
  const predicate = oscalTaskPredicateMap[field].predicate;
  let statements;
  if (Array.isArray(itemIris)) {
    statements = itemIris
      .map((itemIri) => `${iri} ${predicate} ${itemIri}`)
      .join(".\n        ")
    }
  else {
    if (!itemIris.startsWith('<')) itemIris = `<${itemIris}>`;
    statements = `${iri} ${predicate} ${itemIris}`;
  }
  return `
  DELETE DATA {
    GRAPH ${iri} {
      ${statements}
    }
  }
  `
}


// Predicate Maps
export const activityPredicateMap = {
  id: {
      predicate: "<http://darklight.ai/ns/common#id>",
      binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"`: null, this.predicate, "id");},
      optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));}
  },
  object_type: {
    predicate: "<http://darklight.ai/ns/common#object_type>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"` : null,  this.predicate, "object_type");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
  created: {
    predicate: "<http://darklight.ai/ns/common#created>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"^^xsd:dateTime` : null,  this.predicate, "created");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
  modified: {
    predicate: "<http://darklight.ai/ns/common#modified>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"^^xsd:dateTime` : null,  this.predicate, "modified");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
  labels: {
    predicate: "<http://darklight.ai/ns/common#labels>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"`: null, this.predicate, "labels");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
  label_name: {
    predicate: "<http://darklight.ai/ns/common#labels>/<http://darklight.ai/ns/common#name>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"`: null, this.predicate, "label_name");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
  links: {
    predicate: "<http://csrc.nist.gov/ns/oscal/common#links>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"` : null,  this.predicate, "links");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
  remarks: {
    predicate: "<http://csrc.nist.gov/ns/oscal/common#remarks>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"` : null,  this.predicate, "remarks");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
  // relationships: {
  //   predicate: "<http://darklight.ai/ns/common#relationships>",
  //   binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"` : null,  this.predicate, "relationships");},
  //   optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  // },
  name: {
    predicate: "<http://csrc.nist.gov/ns/oscal/common#name>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"` : null,  this.predicate, "name");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
  description: {
    predicate: "<http://csrc.nist.gov/ns/oscal/common#description>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"` : null,  this.predicate, "description");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
  methods: {
    predicate: "<http://csrc.nist.gov/ns/oscal/assessment/common#methods>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"` : null,  this.predicate, "methods");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
  steps: {
    predicate: "<http://csrc.nist.gov/ns/oscal/assessment/common#steps>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"` : null,  this.predicate, "steps");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
  related_controls: {
    predicate: "<http://csrc.nist.gov/ns/oscal/assessment/common#related_controls>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"` : null,  this.predicate, "related_controls");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
  responsible_roles: {
    predicate: "<http://csrc.nist.gov/ns/oscal/common#responsible_roles>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"` : null,  this.predicate, "responsible_roles");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
}
export const actorPredicateMap = {
  id: {
      predicate: "<http://darklight.ai/ns/common#id>",
      binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"`: null, this.predicate, "id");},
      optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value))}
  },
  object_type: {
    predicate: "<http://darklight.ai/ns/common#object_type>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"` : null,  this.predicate, "object_type");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
  links: {
    predicate: "<http://csrc.nist.gov/ns/oscal/common#links>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"` : null,  this.predicate, "links");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
  actor_type: {
    predicate: "<http://csrc.nist.gov/ns/oscal/assessment/common#actor_type>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"` : null,  this.predicate, "actor_type");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
  actor_ref: {
    predicate: "<http://csrc.nist.gov/ns/oscal/assessment/common#actor_ref>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"` : null,  this.predicate, "actor_ref");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
  role_ref: {
    predicate: "<http://csrc.nist.gov/ns/oscal/common#role>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"` : null,  this.predicate, "role_ref");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
}
export const assessmentAssetPredicateMap = {
  id: {
    predicate: "<http://darklight.ai/ns/common#id>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"`: null, this.predicate, "id");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value))}
  },
  object_type: {
    predicate: "<http://darklight.ai/ns/common#object_type>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"` : null,  this.predicate, "object_type");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
  components: {
    predicate: "<http://csrc.nist.gov/ns/oscal/common#components>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"` : null,  this.predicate, "components");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
  assessment_platforms: {
    predicate: "<http://csrc.nist.gov/ns/oscal/assessment/common#assessment_platforms>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"` : null,  this.predicate, "assessment_platforms");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
}
export const assessmentPlatformPredicateMap = {
  id: {
    predicate: "<http://darklight.ai/ns/common#id>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"`: null, this.predicate, "id");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value))}
  },
  object_type: {
    predicate: "<http://darklight.ai/ns/common#object_type>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"` : null,  this.predicate, "object_type");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
  created: {
    predicate: "<http://darklight.ai/ns/common#created>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"^^xsd:dateTime` : null,  this.predicate, "created");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
  modified: {
    predicate: "<http://darklight.ai/ns/common#modified>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"^^xsd:dateTime` : null,  this.predicate, "modified");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
  labels: {
    predicate: "<http://darklight.ai/ns/common#labels>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"`: null, this.predicate, "labels");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
  label_name: {
    predicate: "<http://darklight.ai/ns/common#labels>/<http://darklight.ai/ns/common#name>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"`: null, this.predicate, "label_name");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
  links: {
    predicate: "<http://csrc.nist.gov/ns/oscal/common#links>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"` : null,  this.predicate, "links");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
  remarks: {
    predicate: "<http://csrc.nist.gov/ns/oscal/common#remarks>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"` : null,  this.predicate, "remarks");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
  // relationships: {
  //   predicate: "<http://darklight.ai/ns/common#relationships>",
  //   binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"` : null,  this.predicate, "relationships");},
  //   optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  // },
  name: {
    predicate: "<http://csrc.nist.gov/ns/oscal/common#name>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"` : null,  this.predicate, "name");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
  description: {
    predicate: "<http://csrc.nist.gov/ns/oscal/common#description>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"` : null,  this.predicate, "description");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
  uses_components: {
    predicate: "<http://csrc.nist.gov/ns/oscal/assessment/common#uses_components>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"` : null,  this.predicate, "uses_components");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
}
export const assessmentSubjectPredicateMap = {
  id: {
    predicate: "<http://darklight.ai/ns/common#id>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"`: null, this.predicate, "id");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value))}
  },
  object_type: {
    predicate: "<http://darklight.ai/ns/common#object_type>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"` : null,  this.predicate, "object_type");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
  links: {
    predicate: "<http://csrc.nist.gov/ns/oscal/common#links>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"` : null,  this.predicate, "links");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
  remarks: {
    predicate: "<http://csrc.nist.gov/ns/oscal/common#remarks>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"` : null,  this.predicate, "remarks");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
  subject_type: {
    predicate: "<http://csrc.nist.gov/ns/oscal/assessment/common#subject_type>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"` : null,  this.predicate, "subject_type");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
  description: {
    predicate: "<http://csrc.nist.gov/ns/oscal/common#description>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"` : null,  this.predicate, "description");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
  include_all: {
    predicate: "<http://csrc.nist.gov/ns/oscal/assessment/common#include_all>",
    binding: function (iri, value) { return parameterizePredicate(iri, value !== undefined ? `"${value}"^^xsd:boolean` : null, this.predicate, "include_all")},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },

  include_subjects: {
    predicate: "<http://csrc.nist.gov/ns/oscal/assessment/common#include_subjects>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"` : null,  this.predicate, "include_subjects");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
  exclude_subjects: {
    predicate: "<http://csrc.nist.gov/ns/oscal/assessment/common#exclude_subjects>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"` : null,  this.predicate, "exclude_subjects");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
}
export const associatedActivityPredicateMap = {
  id: {
      predicate: "<http://darklight.ai/ns/common#id>",
      binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"`: null, this.predicate, "id");},
      optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value))}
  },
  object_type: {
    predicate: "<http://darklight.ai/ns/common#object_type>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"` : null,  this.predicate, "object_type");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
  links: {
    predicate: "<http://csrc.nist.gov/ns/oscal/common#links>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"` : null,  this.predicate, "links");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
  remarks: {
    predicate: "<http://csrc.nist.gov/ns/oscal/common#remarks>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"` : null,  this.predicate, "remarks");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
  activity_id: {
    predicate: "<http://csrc.nist.gov/ns/oscal/assessment/common#activity_ref>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"` : null,  this.predicate, "activity_id");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
  responsible_roles: {
    predicate: "<http://csrc.nist.gov/ns/oscal/common#responsible_roles>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"` : null,  this.predicate, "responsible_roles");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
  subjects: {
    predicate: "<http://csrc.nist.gov/ns/oscal/assessment/common#assessment_subjects>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"` : null,  this.predicate, "subjects");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
}
export const characterizationPredicateMap = {
  id: {
    predicate: "<http://darklight.ai/ns/common#id>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"`: null, this.predicate, "id");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value))}
  },
  object_type: {
    predicate: "<http://darklight.ai/ns/common#object_type>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"` : null,  this.predicate, "object_type");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
  created: {
    predicate: "<http://darklight.ai/ns/common#created>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"^^xsd:dateTime` : null,  this.predicate, "created");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
  modified: {
    predicate: "<http://darklight.ai/ns/common#modified>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"^^xsd:dateTime` : null,  this.predicate, "modified");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
  links: {
    predicate: "<http://csrc.nist.gov/ns/oscal/common#links>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"` : null,  this.predicate, "links");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
  remarks: {
    predicate: "<http://csrc.nist.gov/ns/oscal/common#remarks>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"` : null,  this.predicate, "remarks");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
  origins: {
    predicate: "<http://csrc.nist.gov/ns/oscal/assessment/common#origins>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"` : null,  this.predicate, "origins");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
  facets: {
    predicate: "<http://csrc.nist.gov/ns/oscal/assessment/common#facets>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"` : null,  this.predicate, "facets");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
}
export const evidencePredicateMap = {
  id: {
    predicate: "<http://darklight.ai/ns/common#id>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"`: null, this.predicate, "id");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value))}
  },
  object_type: {
    predicate: "<http://darklight.ai/ns/common#object_type>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"` : null,  this.predicate, "object_type");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
  created: {
    predicate: "<http://darklight.ai/ns/common#created>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"^^xsd:dateTime` : null,  this.predicate, "created");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
  modified: {
    predicate: "<http://darklight.ai/ns/common#modified>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"^^xsd:dateTime` : null,  this.predicate, "modified");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
  links: {
    predicate: "<http://csrc.nist.gov/ns/oscal/common#links>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"` : null,  this.predicate, "links");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
  remarks: {
    predicate: "<http://csrc.nist.gov/ns/oscal/common#remarks>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"` : null,  this.predicate, "remarks");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
  description: {
    predicate: "<http://csrc.nist.gov/ns/oscal/assessment/common#description>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"` : null,  this.predicate, "description");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
  href: {
    predicate: "<http://csrc.nist.gov/ns/oscal/common#href>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"^^xsd:anyURI` : null,  this.predicate, "href");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
}
export const facetPredicateMap = {
  id: {
    predicate: "<http://darklight.ai/ns/common#id>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"`: null, this.predicate, "id");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value))}
  },
  object_type: {
    predicate: "<http://darklight.ai/ns/common#object_type>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"` : null,  this.predicate, "object_type");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
  links: {
    predicate: "<http://csrc.nist.gov/ns/oscal/common#links>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"` : null,  this.predicate, "links");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
  remarks: {
    predicate: "<http://csrc.nist.gov/ns/oscal/common#remarks>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"` : null,  this.predicate, "remarks");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
  risk_state: {
    predicate: "<http://csrc.nist.gov/ns/oscal/assessment/common#risk_state>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"` : null,  this.predicate, "risk_state");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
  source_system: {
    predicate: "<http://csrc.nist.gov/ns/oscal/common#source_system>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"^^xsd:anyURI` : null,  this.predicate, "source_system");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
  facet_name: {
    predicate: "<http://csrc.nist.gov/ns/oscal/assessment/common#facet_name>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"` : null,  this.predicate, "facet_name");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
  facet_value: {
    predicate: "<http://csrc.nist.gov/ns/oscal/assessment/common#facet_value>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"` : null,  this.predicate, "facet_value");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
}
export const logEntryAuthorPredicateMap = {
  id: {
    predicate: "<http://darklight.ai/ns/common#id>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"`: null, this.predicate, "id");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value))}
  },
  object_type: {
    predicate: "<http://darklight.ai/ns/common#object_type>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"` : null,  this.predicate, "object_type");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
  party: {
    predicate: "<http://csrc.nist.gov/ns/oscal/common#party>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"` : null,  this.predicate, "party");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
  party_name: {
    predicate: "<http://csrc.nist.gov/ns/oscal/common#party>/<http://csrc.nist.gov/ns/oscal/common#name>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"` : null,  this.predicate, "party_name");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
  party_type: {
    predicate: "<http://csrc.nist.gov/ns/oscal/common#party>/<http://csrc.nist.gov/ns/oscal/common#party_type>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"` : null,  this.predicate, "party_type");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
  role: {
    predicate: "<http://csrc.nist.gov/ns/oscal/common#role>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"` : null,  this.predicate, "role");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
}
export const mitigatingFactorPredicateMap = {
  id: {
      predicate: "<http://darklight.ai/ns/common#id>",
      binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"`: null, this.predicate, "id");},
      optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value))}
  },
  object_type: {
    predicate: "<http://darklight.ai/ns/common#object_type>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"` : null,  this.predicate, "object_type");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
  created: {
    predicate: "<http://darklight.ai/ns/common#created>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"^^xsd:dateTime` : null,  this.predicate, "created");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
  modified: {
    predicate: "<http://darklight.ai/ns/common#modified>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"^^xsd:dateTime` : null,  this.predicate, "modified");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
  labels: {
    predicate: "<http://darklight.ai/ns/common#labels>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"`: null, this.predicate, "labels");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
  label_name: {
    predicate: "<http://darklight.ai/ns/common#labels>/<http://darklight.ai/ns/common#name>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"`: null, this.predicate, "label_name");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
  links: {
    predicate: "<http://csrc.nist.gov/ns/oscal/common#links>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"` : null,  this.predicate, "links");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
  remarks: {
    predicate: "<http://csrc.nist.gov/ns/oscal/common#remarks>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"` : null,  this.predicate, "remarks");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
  // relationships: {
  //   predicate: "<http://darklight.ai/ns/common#relationships>",
  //   binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"` : null,  this.predicate, "relationships");},
  //   optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  // },
  // implementation: {
  //   predicate: "<http://csrc.nist.gov/ns/oscal/assessment/common#implementation>",
  //   binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"` : null,  this.predicate, "implementation");},
  //   optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  // },
  description: {
    predicate: "<http://csrc.nist.gov/ns/oscal/common#description>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"` : null,  this.predicate, "description");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
  subjects: {
    predicate: "<http://csrc.nist.gov/ns/oscal/assessment/common#subjects>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"` : null,  this.predicate, "subjects");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
}
export const observationPredicateMap = {
  id: {
      predicate: "<http://darklight.ai/ns/common#id>",
      binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"`: null, this.predicate, "id");},
      optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value))}
  },
  entity_type: {
    predicate: "<http://darklight.ai/ns/common#object_type>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"` : null,  this.predicate, "object_type");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
  created: {
    predicate: "<http://darklight.ai/ns/common#created>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"^^xsd:dateTime` : null,  this.predicate, "created");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
  modified: {
    predicate: "<http://darklight.ai/ns/common#modified>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"^^xsd:dateTime` : null,  this.predicate, "modified");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
  labels: {
    predicate: "<http://darklight.ai/ns/common#labels>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"`: null, this.predicate, "labels");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
  label_name: {
    predicate: "<http://darklight.ai/ns/common#labels>/<http://darklight.ai/ns/common#name>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"`: null, this.predicate, "label_name");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
  links: {
    predicate: "<http://csrc.nist.gov/ns/oscal/common#links>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"` : null,  this.predicate, "links");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
  remarks: {
    predicate: "<http://csrc.nist.gov/ns/oscal/common#remarks>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"` : null,  this.predicate, "remarks");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
  // relationships: {
  //   predicate: "<http://darklight.ai/ns/common#relationships>",
  //   binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"` : null,  this.predicate, "relationships");},
  //   optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  // },
  name: {
    predicate: "<http://csrc.nist.gov/ns/oscal/common#name>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"` : null,  this.predicate, "name");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
  description: {
    predicate: "<http://csrc.nist.gov/ns/oscal/common#description>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"` : null,  this.predicate, "description");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
  methods: {
    predicate: "<http://csrc.nist.gov/ns/oscal/assessment/common#methods>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"` : null,  this.predicate, "methods");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
  observation_types: {
    predicate: "<http://csrc.nist.gov/ns/oscal/assessment/common#observation_types>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"` : null,  this.predicate, "observation_types");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
  origins: {
    predicate: "<http://csrc.nist.gov/ns/oscal/assessment/common#origins>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"` : null,  this.predicate, "origins");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
  subjects: {
    predicate: "<http://csrc.nist.gov/ns/oscal/assessment/common#subjects>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"` : null,  this.predicate, "subjects");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
  relevant_evidence: {
    predicate: "<http://csrc.nist.gov/ns/oscal/assessment/common#relevant_evidence>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"` : null,  this.predicate, "relevant_evidence");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
  collected: {
    predicate: "<http://csrc.nist.gov/ns/oscal/assessment/common#collected>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"^^xsd:dateTime` : null,  this.predicate, "collected");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
  expires: {
    predicate: "<http://csrc.nist.gov/ns/oscal/assessment/common#expires>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"^^xsd:dateTime` : null,  this.predicate, "expires");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
}
export const originPredicateMap = {
  id: {
    predicate: "<http://darklight.ai/ns/common#id>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"`: null, this.predicate, "id");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value))}
  },
  object_type: {
    predicate: "<http://darklight.ai/ns/common#object_type>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"` : null,  this.predicate, "object_type");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
  origin_actors: {
    predicate: "<http://csrc.nist.gov/ns/oscal/assessment/common#origin_actors>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"` : null,  this.predicate, "origin_actors");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
  related_tasks: {
    predicate: "<http://csrc.nist.gov/ns/oscal/assessment/common#related_tasks>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"` : null,  this.predicate, "related_tasks");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
}
export const oscalTaskPredicateMap = {
  id: {
      predicate: "<http://darklight.ai/ns/common#id>",
      binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"`: null, this.predicate, "id");},
      optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value))}
  },
  object_type: {
    predicate: "<http://darklight.ai/ns/common#object_type>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"` : null,  this.predicate, "object_type");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
  created: {
    predicate: "<http://darklight.ai/ns/common#created>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"^^xsd:dateTime` : null,  this.predicate, "created");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
  modified: {
    predicate: "<http://darklight.ai/ns/common#modified>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"^^xsd:dateTime` : null,  this.predicate, "modified");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
  labels: {
    predicate: "<http://darklight.ai/ns/common#labels>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"`: null, this.predicate, "labels");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
  label_name: {
    predicate: "<http://darklight.ai/ns/common#labels>/<http://darklight.ai/ns/common#name>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"`: null, this.predicate, "label_name");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
  links: {
    predicate: "<http://csrc.nist.gov/ns/oscal/common#links>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"` : null,  this.predicate, "links");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
  remarks: {
    predicate: "<http://csrc.nist.gov/ns/oscal/common#remarks>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"` : null,  this.predicate, "remarks");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
  // relationships: {
  //   predicate: "<http://darklight.ai/ns/common#relationships>",
  //   binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"` : null,  this.predicate, "relationships");},
  //   optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  // },
  name: {
    predicate: "<http://csrc.nist.gov/ns/oscal/common#name>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"` : null,  this.predicate, "name");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
  description: {
    predicate: "<http://csrc.nist.gov/ns/oscal/common#description>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"` : null,  this.predicate, "description");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
  task_type: {
    predicate: "<http://csrc.nist.gov/ns/oscal/assessment/common#task_type>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"` : null,  this.predicate, "task_type");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
  on_date: {
    predicate: "<http://csrc.nist.gov/ns/oscal/assessment/common#on_date>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"^^xsd:dateTime` : null,  this.predicate, "on_date");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
  start_date: {
    predicate: "<http://csrc.nist.gov/ns/oscal/assessment/common#start_date>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"^^xsd:dateTime` : null,  this.predicate, "start_date");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
  end_date: {
    predicate: "<http://csrc.nist.gov/ns/oscal/assessment/common#end_date>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"^^xsd:dateTime` : null,  this.predicate, "end_date");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
  frequency_period: {
    predicate: "<http://csrc.nist.gov/ns/oscal/assessment/common#frequency_period>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"^^xsd:positiveInteger` : null,  this.predicate, "frequency_period");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
  frequency_unit: {
    predicate: "<http://csrc.nist.gov/ns/oscal/assessment/common#time_unit>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"` : null,  this.predicate, "frequency_unit");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
  related_tasks: {
    predicate: "<http://csrc.nist.gov/ns/oscal/assessment/common#related_tasks>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"` : null,  this.predicate, "related_tasks");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
  task_dependencies: {
    predicate: "<http://csrc.nist.gov/ns/oscal/assessment/common#task_dependencies>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"` : null,  this.predicate, "task_dependencies");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
  associated_activities: {
    predicate: "<http://csrc.nist.gov/ns/oscal/assessment/common#associated_activities>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"` : null,  this.predicate, "associated_activities");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
  subjects: {
    predicate: "<http://csrc.nist.gov/ns/oscal/assessment/common#subjects>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"` : null,  this.predicate, "subjects");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
  responsible_roles: {
    predicate: "<http://csrc.nist.gov/ns/oscal/common#responsible_roles>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"` : null,  this.predicate, "responsible_roles");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
}
export const requiredAssetPredicateMap = {
  id: {
    predicate: "<http://darklight.ai/ns/common#id>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"`: null, this.predicate, "id");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value))}
  },
  object_type: {
    predicate: "<http://darklight.ai/ns/common#object_type>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"` : null,  this.predicate, "object_type");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
  created: {
    predicate: "<http://darklight.ai/ns/common#created>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"^^xsd:dateTime` : null,  this.predicate, "created");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
  modified: {
    predicate: "<http://darklight.ai/ns/common#modified>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"^^xsd:dateTime` : null,  this.predicate, "modified");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
  labels: {
    predicate: "<http://darklight.ai/ns/common#labels>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"`: null, this.predicate, "labels");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
  label_name: {
    predicate: "<http://darklight.ai/ns/common#labels>/<http://darklight.ai/ns/common#name>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"`: null, this.predicate, "label_name");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
  links: {
    predicate: "<http://csrc.nist.gov/ns/oscal/common#links>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"` : null,  this.predicate, "links");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
  remarks: {
    predicate: "<http://csrc.nist.gov/ns/oscal/common#remarks>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"` : null,  this.predicate, "remarks");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
  name: {
    predicate: "<http://csrc.nist.gov/ns/oscal/common#name>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"` : null,  this.predicate, "name");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
  description: {
    predicate: "<http://csrc.nist.gov/ns/oscal/common#description>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"` : null,  this.predicate, "description");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
  subjects: {
    predicate: "<http://csrc.nist.gov/ns/oscal/assessment/common#subjects>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"` : null,  this.predicate, "subjects");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
}
export const riskPredicateMap = {
  id: {
      predicate: "<http://darklight.ai/ns/common#id>",
      binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"`: null, this.predicate, "id");},
      optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value))}
  },
  object_type: {
    predicate: "<http://darklight.ai/ns/common#object_type>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"` : null,  this.predicate, "object_type");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
  created: {
    predicate: "<http://darklight.ai/ns/common#created>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"^^xsd:dateTime` : null,  this.predicate, "created");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
  modified: {
    predicate: "<http://darklight.ai/ns/common#modified>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"^^xsd:dateTime` : null,  this.predicate, "modified");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
  labels: {
    predicate: "<http://darklight.ai/ns/common#labels>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"`: null, this.predicate, "labels");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
  label_name: {
    predicate: "<http://darklight.ai/ns/common#labels>/<http://darklight.ai/ns/common#name>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"`: null, this.predicate, "label_name");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
  links: {
    predicate: "<http://csrc.nist.gov/ns/oscal/common#links>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"` : null,  this.predicate, "links");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
  remarks: {
    predicate: "<http://csrc.nist.gov/ns/oscal/common#remarks>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"` : null,  this.predicate, "remarks");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
  // relationships: {
  //   predicate: "<http://darklight.ai/ns/common#relationships>",
  //   binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"` : null,  this.predicate, "relationships");},
  //   optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  // },
  name: {
    predicate: "<http://csrc.nist.gov/ns/oscal/common#name>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"` : null,  this.predicate, "name");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
  description: {
    predicate: "<http://csrc.nist.gov/ns/oscal/common#description>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"` : null,  this.predicate, "description");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
  origins: {
    predicate: "<http://csrc.nist.gov/ns/oscal/assessment/common#origins>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"` : null,  this.predicate, "origins");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
  statement: {
    predicate: "<http://csrc.nist.gov/ns/oscal/assessment/common#statement>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"` : null,  this.predicate, "statement");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
  risk_status: {
    predicate: "<http://csrc.nist.gov/ns/oscal/assessment/common#risk_status>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"` : null,  this.predicate, "risk_status");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
  threat_refs: {
    predicate: "<http://csrc.nist.gov/ns/oscal/assessment/common#threat_refs>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"` : null,  this.predicate, "threat_refs");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
  characterizations: {
    predicate: "<http://csrc.nist.gov/ns/oscal/assessment/common#characterizations>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"` : null,  this.predicate, "characterizations");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
  mitigating_factors: {
    predicate: "<http://csrc.nist.gov/ns/oscal/assessment/common#mitigating_factors>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"` : null,  this.predicate, "mitigating_factors");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
  collected: {
    predicate: "<http://csrc.nist.gov/ns/oscal/assessment/common#related_observations>/<http://csrc.nist.gov/ns/oscal/assessment/common#collected>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"^^xsd:dateTime` : null,  this.predicate, "collected");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
  deadline: {
    predicate: "<http://csrc.nist.gov/ns/oscal/assessment/common#deadline>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"^^xsd:dateTime` : null,  this.predicate, "deadline");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
  remediations: {
    predicate: "<http://csrc.nist.gov/ns/oscal/assessment/common#remediations>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"` : null,  this.predicate, "remediations");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
  risk_log: {
    predicate: "<http://csrc.nist.gov/ns/oscal/assessment/common#risk_log>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"` : null,  this.predicate, "risk_log");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
  related_observations: {
    predicate: "<http://csrc.nist.gov/ns/oscal/assessment/common#related_observations>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"` : null,  this.predicate, "related_observations");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
  related_observation_ids: {
    predicate: "<http://csrc.nist.gov/ns/oscal/assessment/common#related_observations>/<http://darklight.ai/ns/common#id>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"` : null,  this.predicate, "related_observation_ids");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
  false_positive: {
    predicate: "<http://csrc.nist.gov/ns/oscal/assessment/common#false_positive>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"^^xsd:boolean` : null,  this.predicate, "false_positive");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
    extension_property: 'false-positive',
  },
  accepted: {
    predicate: "<http://csrc.nist.gov/ns/oscal/assessment/common#accepted>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"^^xsd:boolean` : null,  this.predicate, "accepted");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
    extension_property: 'accepted',
  },
  risk_adjusted: {
    predicate: "<http://csrc.nist.gov/ns/oscal/assessment/common#risk_adjusted>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"^^xsd:boolean` : null,  this.predicate, "risk_adjusted");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
    extension_property: 'risk-adjusted',
  },
  priority: {
    predicate: "<http://csrc.nist.gov/ns/oscal/assessment/common#priority>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"^^xsd:nonNegativeInteger` : null,  this.predicate, "priority");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
    extension_property: 'priority',
  },
  vendor_dependency: {
    predicate: "<http://fedramp.gov/ns/oscal#vendor_dependency>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"^^xsd:boolean` : null,  this.predicate, "vendor_dependency");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
  impacted_control_id: {
    predicate: "<http://fedramp.gov/ns/oscal#impacted_control_id>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"` : null,  this.predicate, "impacted_control_id");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
  operational_requirement: {
    predicate: "<http://fedramp.gov/ns/oscal#operational_requirement>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"` : null,  this.predicate, "operational_requirement");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
  // Predicate mappings used to gather data for POAM ID
  poam_id: {
    predicate: "^<http://csrc.nist.gov/ns/oscal/assessment/common#related_risks>/<http://fedramp.gov/ns/oscal#poam_id>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"` : null,  this.predicate, "poam_id");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
  // Predicate mappings used to gather data for risk level scoring
  cvss2_base_score: {
    predicate: "<http://csrc.nist.gov/ns/oscal/assessment/common#characterizations>/<http://csrc.nist.gov/ns/oscal/assessment/common#facets>/<http://csrc.nist.gov/ns/oscal/assessment/common#cvss20_base_score>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"^^xsd:decimal` : null,  this.predicate, "cvss2_base_score");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
  cvss2_temporal_score: {
    predicate: "<http://csrc.nist.gov/ns/oscal/assessment/common#characterizations>/<http://csrc.nist.gov/ns/oscal/assessment/common#facets>/<http://csrc.nist.gov/ns/oscal/assessment/common#cvss20_temporal_score>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"^^xsd:decimal` : null,  this.predicate, "cvss2_temporal_score");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
  // cvss2_environmental_score: {
  //   predicate: "<http://csrc.nist.gov/ns/oscal/assessment/common#characterizations>/<http://csrc.nist.gov/ns/oscal/assessment/common#facets>/<http://csrc.nist.gov/ns/oscal/assessment/common#cvss20_environmental_score>",
  //   binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"^^xsd:decimal` : null,  this.predicate, "cvss2_environmental_score");},
  //   optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  // },
  cvss3_base_score: {
    predicate: "<http://csrc.nist.gov/ns/oscal/assessment/common#characterizations>/<http://csrc.nist.gov/ns/oscal/assessment/common#facets>/<http://csrc.nist.gov/ns/oscal/assessment/common#cvss30_base_score>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"^^xsd:decimal` : null,  this.predicate, "cvss3_base_score");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
  cvss3_temporal_score: {
    predicate: "<http://csrc.nist.gov/ns/oscal/assessment/common#characterizations>/<http://csrc.nist.gov/ns/oscal/assessment/common#facets>/<http://csrc.nist.gov/ns/oscal/assessment/common#cvss30_temporal_score>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"^^xsd:decimal` : null,  this.predicate, "cvss3_temporal_score");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
  // cvss3_environmental_score: {
  //   predicate: "<http://csrc.nist.gov/ns/oscal/assessment/common#cvss30_environmental_score>",
  //   binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"^^xsd:decimal` : null,  this.predicate, "cvss3_environmental_score");},
  //   optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  // },
  available_exploit: {
    predicate: "<http://csrc.nist.gov/ns/oscal/assessment/common#characterizations>/<http://csrc.nist.gov/ns/oscal/assessment/common#facets>/<http://csrc.nist.gov/ns/oscal/assessment/common#exploit_available>",
    binding: function (iri, value) { return parameterizePredicate(iri, value !== undefined ? `"${value}"^^xsd:boolean` : null, this.predicate, "available_exploit");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
  exploitability_ease: {
    predicate: "<http://csrc.nist.gov/ns/oscal/assessment/common#characterizations>/<http://csrc.nist.gov/ns/oscal/assessment/common#facets>/<http://csrc.nist.gov/ns/oscal/assessment/common#exploitability>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"` : null,  this.predicate, "exploitability_ease");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
  // Predicate mappings used to gather data for risk response
  // remediation_response_date: {
  //   predicate: "<http://csrc.nist.gov/ns/oscal/assessment/common#remediations>/<http://darklight.ai/ns/common#modified>",
  //   binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"^^xsd:dateTime` : null,  this.predicate, "remediation_response_date");},
  //   optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  // },
  remediation_type: {
    predicate: "<http://csrc.nist.gov/ns/oscal/assessment/common#remediations>/<http://csrc.nist.gov/ns/oscal/assessment/common#response_type>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"` : null,  this.predicate, "remediation_type");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
  remediation_lifecycle: {
    predicate: "<http://csrc.nist.gov/ns/oscal/assessment/common#remediations>/<http://csrc.nist.gov/ns/oscal/assessment/common#lifecycle>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"` : null,  this.predicate, "remediation_lifecycle");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
  remediation_timestamp: {
    predicate: "<http://csrc.nist.gov/ns/oscal/assessment/common#remediations>/<http://darklight.ai/ns/common#modified>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"^^xsd:dateTime` : null,  this.predicate, "remediation_timestamp");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
  observation_subject: {
    predicate: "<http://csrc.nist.gov/ns/oscal/assessment/common#related_observations>/<http://csrc.nist.gov/ns/oscal/assessment/common#subjects>/<http://darklight.ai/ns/oscal/assessment/common#subject_context>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"` : null,  this.predicate, "observation_subject");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  }
}
export const riskLogPredicateMap = {
  id: {
    predicate: "<http://darklight.ai/ns/common#id>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"`: null, this.predicate, "id");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value))}
  },
  object_type: {
    predicate: "<http://darklight.ai/ns/common#object_type>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"` : null,  this.predicate, "object_type");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
  created: {
    predicate: "<http://darklight.ai/ns/common#created>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"^^xsd:dateTime` : null,  this.predicate, "created");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
  modified: {
    predicate: "<http://darklight.ai/ns/common#modified>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"^^xsd:dateTime` : null,  this.predicate, "modified");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
  labels: {
    predicate: "<http://darklight.ai/ns/common#labels>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"`: null, this.predicate, "labels");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
  label_name: {
    predicate: "<http://darklight.ai/ns/common#labels>/<http://darklight.ai/ns/common#name>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"`: null, this.predicate, "label_name");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
  links: {
    predicate: "<http://csrc.nist.gov/ns/oscal/common#links>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"` : null,  this.predicate, "links");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
  remarks: {
    predicate: "<http://csrc.nist.gov/ns/oscal/common#remarks>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"` : null,  this.predicate, "remarks");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
  // relationships: {
  //   predicate: "<http://darklight.ai/ns/common#relationships>",
  //   binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"` : null,  this.predicate, "relationships");},
  //   optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  // },
  entry_type: {
      predicate: "<http://csrc.nist.gov/ns/oscal/assessment/common#entry_type>",
      binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"` : null,  this.predicate, "entry_type");},
      optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
    },
  name: {
    predicate: "<http://csrc.nist.gov/ns/oscal/common#name>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"` : null,  this.predicate, "name");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
  description: {
    predicate: "<http://csrc.nist.gov/ns/oscal/common#description>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"` : null,  this.predicate, "description");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
  event_start: {
    predicate: "<http://csrc.nist.gov/ns/oscal/common#event_start>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"^^xsd:dateTime` : null,  this.predicate, "event_start");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
  event_end: {
    predicate: "<http://csrc.nist.gov/ns/oscal/common#event_end>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"^^xsd:dateTime` : null,  this.predicate, "event_end");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
  logged_by: {
    predicate: "<http://csrc.nist.gov/ns/oscal/assessment/common#logged_by>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"` : null,  this.predicate, "logged_by");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
  status_change: {
    predicate: "<http://csrc.nist.gov/ns/oscal/assessment/common#status_change>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"` : null,  this.predicate, "status_change");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
  related_responses: {
    predicate: "<http://csrc.nist.gov/ns/oscal/assessment/common#related_responses>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"` : null,  this.predicate, "related_responses");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
}
export const riskResponsePredicateMap = {
  id: {
      predicate: "<http://darklight.ai/ns/common#id>",
      binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"`: null, this.predicate, "id");},
      optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value))}
  },
  object_type: {
    predicate: "<http://darklight.ai/ns/common#object_type>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"` : null,  this.predicate, "object_type");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
  created: {
    predicate: "<http://darklight.ai/ns/common#created>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"^^xsd:dateTime` : null,  this.predicate, "created");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
  modified: {
    predicate: "<http://darklight.ai/ns/common#modified>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"^^xsd:dateTime` : null,  this.predicate, "modified");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
  labels: {
    predicate: "<http://darklight.ai/ns/common#labels>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"`: null, this.predicate, "labels");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
  label_name: {
    predicate: "<http://darklight.ai/ns/common#labels>/<http://darklight.ai/ns/common#name>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"`: null, this.predicate, "label_name");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
  links: {
    predicate: "<http://csrc.nist.gov/ns/oscal/common#links>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"` : null,  this.predicate, "links");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
  remarks: {
    predicate: "<http://csrc.nist.gov/ns/oscal/common#remarks>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"` : null,  this.predicate, "remarks");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
  // relationships: {
  //   predicate: "<http://darklight.ai/ns/common#relationships>",
  //   binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"` : null,  this.predicate, "relationships");},
  //   optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  // },
  name: {
    predicate: "<http://csrc.nist.gov/ns/oscal/common#name>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"` : null,  this.predicate, "name");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
  description: {
    predicate: "<http://csrc.nist.gov/ns/oscal/common#description>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"` : null,  this.predicate, "description");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
  response_type: {
    predicate: "<http://csrc.nist.gov/ns/oscal/assessment/common#response_type>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"` : null,  this.predicate, "response_type");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
    extension_property: 'type',
  },
  lifecycle: {
    predicate: "<http://csrc.nist.gov/ns/oscal/assessment/common#lifecycle>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"` : null,  this.predicate, "lifecycle");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
  origins: {
    predicate: "<http://csrc.nist.gov/ns/oscal/assessment/common#origins>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"` : null,  this.predicate, "origins");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
  required_assets: {
    predicate: "<http://csrc.nist.gov/ns/oscal/assessment/common#required_assets>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"` : null,  this.predicate, "required_assets");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
  tasks: {
    predicate: "<http://csrc.nist.gov/ns/oscal/assessment/common#tasks>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"` : null,  this.predicate, "tasks");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
}
export const subjectPredicateMap = {
  id: {
    predicate: "<http://darklight.ai/ns/common#id>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"`: null, this.predicate, "id");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value))}
  },
  object_type: {
    predicate: "<http://darklight.ai/ns/common#object_type>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"` : null,  this.predicate, "object_type");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
  links: {
    predicate: "<http://csrc.nist.gov/ns/oscal/common#links>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"` : null,  this.predicate, "links");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
  remarks: {
    predicate: "<http://csrc.nist.gov/ns/oscal/common#remarks>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"` : null,  this.predicate, "remarks");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
  name: {
    predicate: "<http://csrc.nist.gov/ns/oscal/common#name>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"` : null,  this.predicate, "name");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
  subject_type: {
    predicate: "<http://csrc.nist.gov/ns/oscal/assessment/common#subject_type>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"` : null,  this.predicate, "subject_type");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
  subject_ref: {
    predicate: "<http://csrc.nist.gov/ns/oscal/assessment/common#subject_ref>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"` : null,  this.predicate, "subject_ref");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
  subject_context: {
    predicate: "<http://darklight.ai/ns/oscal/assessment/common#subject_context>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"` : null,  this.predicate, "subject_context");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
  subject_id: {
    predicate: "<http://csrc.nist.gov/ns/oscal/assessment/common#subject_ref>/<http://darklight.ai/ns/common#id>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"` : null,  this.predicate, "subject_id");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
  subject_name: {
    predicate: "<http://csrc.nist.gov/ns/oscal/assessment/common#subject_ref>/<http://scap.nist.gov/ns/asset-identification#name>|<http://csrc.nist.gov/ns/oscal/assessment/common#subject_ref>/<http://csrc.nist.gov/ns/oscal/common#name>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"` : null,  this.predicate, "subject_name");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
  subject_version: {
    predicate: "<http://csrc.nist.gov/ns/oscal/assessment/common#subject_ref>/<http://scap.nist.gov/ns/asset-identification#version>|<http://csrc.nist.gov/ns/oscal/assessment/common#subject_ref>/<http://csrc.nist.gov/ns/oscal/common#version>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"` : null,  this.predicate, "subject_version");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
  subject_asset_type: {
    predicate: "<http://csrc.nist.gov/ns/oscal/assessment/common#subject_ref>/<http://scap.nist.gov/ns/asset-identification#asset_type>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"` : null, this.predicate, "subject_asset_type");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
  subject_component_type: {
    predicate: "<http://csrc.nist.gov/ns/oscal/assessment/common#subject_ref>/<http://csrc.nist.gov/ns/oscal/common#component_type>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"` : null,  this.predicate, "subject_component_type");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
  subject_location_type: {
    predicate: "<http://csrc.nist.gov/ns/oscal/assessment/common#subject_ref>/<http://csrc.nist.gov/ns/oscal/common#location_type>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"` : null,  this.predicate, "subject_location_type");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
  subject_party_type: {
    predicate: "<http://csrc.nist.gov/ns/oscal/assessment/common#subject_ref>/<http://csrc.nist.gov/ns/oscal/common#party_type>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"` : null,  this.predicate, "subject_party_type");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
}
export const vulnerabilityFacetPredicateMap = {
  id: {
    predicate: "<http://darklight.ai/ns/common#id>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"`: null, this.predicate, "id");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value))}
  },
  object_type: {
    predicate: "<http://darklight.ai/ns/common#object_type>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"` : null,  this.predicate, "object_type");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
  links: {
    predicate: "<http://csrc.nist.gov/ns/oscal/common#links>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"` : null,  this.predicate, "links");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
  remarks: {
    predicate: "<http://csrc.nist.gov/ns/oscal/common#remarks>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"` : null,  this.predicate, "remarks");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
  risk_state: {
    predicate: "<http://csrc.nist.gov/ns/oscal/assessment/common#risk_state>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"` : null,  this.predicate, "risk_state");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
  source_system: {
    predicate: "<http://csrc.nist.gov/ns/oscal/common#source_system>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"^^xsd:anyURI` : null,  this.predicate, "source_system");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
  vulnerability_id: {
    predicate: "<http://csrc.nist.gov/ns/oscal/assessment/common#vulnerability_id>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"` : null,  this.predicate, "vulnerability_id");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
  cvss20_vector_string: {
    predicate: "<http://csrc.nist.gov/ns/oscal/assessment/common#cvss20_vector_string>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"` : null,  this.predicate, "cvss20_vector_string");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
  cvss20_base_score: {
    predicate: "<http://csrc.nist.gov/ns/oscal/assessment/common#cvss20_base_score>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"^^xsd:decimal` : null,  this.predicate, "cvss20_base_score");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
  cvss20_temporal_score: {
    predicate: "<http://csrc.nist.gov/ns/oscal/assessment/common#cvss20_temporal_score>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"^^xsd:decimal` : null,  this.predicate, "cvss20_temporal_score");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
  cvss20_environmental_score: {
    predicate: "<http://csrc.nist.gov/ns/oscal/assessment/common#cvss20_environmental_score>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"^^xsd:decimal` : null,  this.predicate, "cvss20_environmental_score");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
  cvss30_vector_string: {
    predicate: "<http://csrc.nist.gov/ns/oscal/assessment/common#cvss30_vector_string>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"` : null,  this.predicate, "cvss30_vector_string");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
  cvss30_base_score: {
    predicate: "<http://csrc.nist.gov/ns/oscal/assessment/common#cvss30_base_score>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"^^xsd:decimal` : null,  this.predicate, "cvss30_base_score");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
  cvss30_temporal_score: {
    predicate: "<http://csrc.nist.gov/ns/oscal/assessment/common#cvss30_temporal_score>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"^^xsd:decimal` : null,  this.predicate, "cvss30_temporal_score");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
  cvss30_environmental_score: {
    predicate: "<http://csrc.nist.gov/ns/oscal/assessment/common#cvss30_environmental_score>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"^^xsd:decimal` : null,  this.predicate, "cvss30_environmental_score");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
  score_rationale: {
    predicate: "<http://csrc.nist.gov/ns/oscal/assessment/common#score_rationale>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"` : null,  this.predicate, "score_rationale");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
  exploitability: {
    predicate: "<http://csrc.nist.gov/ns/oscal/assessment/common#exploitability>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"` : null,  this.predicate, "exploitability");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
  exploit_available: {
    predicate: "<http://csrc.nist.gov/ns/oscal/assessment/common#exploit_available>",
    binding: function (iri, value) { return parameterizePredicate(iri, value !== undefined ? `"${value}"^^xsd:boolean` : null, this.predicate, "exploit_available");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
}
export const fedrampFacetPredicateMap = {
  id: {
    predicate: "<http://darklight.ai/ns/common#id>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"`: null, this.predicate, "id");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value))}
  },
  object_type: {
    predicate: "<http://darklight.ai/ns/common#object_type>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"` : null,  this.predicate, "object_type");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
  links: {
    predicate: "<http://csrc.nist.gov/ns/oscal/common#links>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"` : null,  this.predicate, "links");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
  remarks: {
    predicate: "<http://csrc.nist.gov/ns/oscal/common#remarks>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"` : null,  this.predicate, "remarks");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
  risk_state: {
    predicate: "<http://csrc.nist.gov/ns/oscal/assessment/common#risk_state>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"` : null,  this.predicate, "risk_state");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
  source_system: {
    predicate: "<http://csrc.nist.gov/ns/oscal/common#source_system>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"^^xsd:anyURI` : null,  this.predicate, "source_system");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
  likelihood: {
    predicate: "<http://csrc.nist.gov/ns/oscal/assessment/common#likelihood>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"` : null,  this.predicate, "likelihood");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
  impact: {
    predicate: "<http://csrc.nist.gov/ns/oscal/assessment/common#impact>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"` : null,  this.predicate, "impact");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
  risk: {
    predicate: "<http://csrc.nist.gov/ns/oscal/assessment/common#risk>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"` : null,  this.predicate, "risk");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
  plugin_file: {
    predicate: "<http://csrc.nist.gov/ns/oscal/assessment/common#plugin_file>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"` : null,  this.predicate, "plugin_file");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
  plugin_family: {
    predicate: "<http://csrc.nist.gov/ns/oscal/assessment/common#pllugin_family>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"` : null,  this.predicate, "plugin_family");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
  plugin_id: {
    predicate: "<http://csrc.nist.gov/ns/oscal/assessment/common#plugin_id>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"` : null,  this.predicate, "plugin_id");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
  plugin_name: {
    predicate: "<http://csrc.nist.gov/ns/oscal/assessment/common#plugin_name>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"` : null,  this.predicate, "plugin_name");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
  plugin_type: {
    predicate: "<http://csrc.nist.gov/ns/oscal/assessment/common#plugin_type>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"` : null,  this.predicate, "plugin_type");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
}
export const oscalFacetPredicateMap = {
  id: {
    predicate: "<http://darklight.ai/ns/common#id>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"`: null, this.predicate, "id");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value))}
  },
  object_type: {
    predicate: "<http://darklight.ai/ns/common#object_type>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"` : null,  this.predicate, "object_type");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
  links: {
    predicate: "<http://csrc.nist.gov/ns/oscal/common#links>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"` : null,  this.predicate, "links");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
  remarks: {
    predicate: "<http://csrc.nist.gov/ns/oscal/common#remarks>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"` : null,  this.predicate, "remarks");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
  risk_state: {
    predicate: "<http://csrc.nist.gov/ns/oscal/assessment/common#risk_state>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"` : null,  this.predicate, "risk_state");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
  source_system: {
    predicate: "<http://csrc.nist.gov/ns/oscal/common#source_system>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"^^xsd:anyURI` : null,  this.predicate, "source_system");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
  likelihood: {
    predicate: "<http://csrc.nist.gov/ns/oscal/assessment/common#likelihood>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"` : null,  this.predicate, "likelihood");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
  impact: {
    predicate: "<http://csrc.nist.gov/ns/oscal/assessment/common#impact>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"` : null,  this.predicate, "impact");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
  risk: {
    predicate: "<http://csrc.nist.gov/ns/oscal/assessment/common#risk>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"` : null,  this.predicate, "risk");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
  severity: {
    predicate: "<http://csrc.nist.gov/ns/oscal/assessment/common#severity>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"` : null,  this.predicate, "severity");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
}

