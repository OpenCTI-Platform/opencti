import { UserInputError } from 'apollo-server-errors';
import conf from '../../../../config/conf';
import { selectObjectIriByIdQuery } from '../../global/global-utils.js';
import { 
  compareValues, 
  filterValues, 
  updateQuery, 
  checkIfValidUUID, 
  validateEnumValue,
  generateId,
  DARKLIGHT_NS
} from '../../utils.js';
import {
  getReducer,
  informationSystemPredicateMap,
  singularizeInformationSystemSchema,
  selectInformationSystemQuery,
  selectInformationSystemByIriQuery,
  selectAllInformationSystemsQuery,
  insertInformationSystemQuery,
  deleteInformationSystemQuery,
  deleteInformationSystemByIriQuery,
  attachToInformationSystemQuery,
  detachFromInformationSystemQuery,
} from '../schema/sparql/informationSystem.js';
import { addToInventoryQuery, removeFromInventoryQuery } from '../../assets/assetUtil.js';
import { createInformationType, findInformationTypeByIri } from './informationType.js';
import { createDescriptionBlock, deleteDescriptionBlockByIri } from './descriptionBlock.js';
import { findComponentByIri } from '../../risk-assessments/component/domain/component.js';
import { findInventoryItemByIri } from '../../risk-assessments/inventory-item/domain/inventoryItem.js';



// Information System
export const findInformationSystemById = async (id, dbName, dataSources, select) => {
  // ensure the id is a valid UUID
  if (!checkIfValidUUID(id)) throw new UserInputError(`Invalid identifier: ${id}`);

  let iri = `<http://cyio.darklight.ai/information-system--${id}>`;
  return findInformationSystemByIri(iri, dbName, dataSources, select);
}

export const findInformationSystemByIri = async (iri, dbName, dataSources, select) => {
  const sparqlQuery = selectInformationSystemByIriQuery(iri, select);
  let response;
  try {
    response = await dataSources.Stardog.queryById({
      dbName,
      sparqlQuery,
      queryId: "Select Information System",
      singularizeSchema: singularizeInformationSystemSchema
    });
  } catch (e) {
    console.log(e)
    throw e
  }
  if (response === undefined || response === null || response.length === 0) return null;

  let { confidentiality, integrity, availability } = await computeSecurityObjectives(response[0].information_types);
  response[0].security_objective_confidentiality = confidentiality;
  response[0].security_objective_integrity = integrity;
  response[0].security_objective_availability = availability;

  // Determine the security sensitivity level
  response[0].security_sensitivity_level = computeSensitivityLevel( confidentiality, 
                                                                    integrity, 
                                                                    availability );

  // if not specified, supply default for privacy designation
  if (response[0].privacy_designation === undefined) {
    response[0].privacy_designation = false;
  }

  // if not specified, determine if system is deemed critical
  if (response[0].critical_system_designation === undefined) {
    response[0].critical_system_designation = await determineCriticalSystemDesignation(
                                                  response[0].security_sensitivity_level, 
                                                  response[0].privacy_designation );
  }

  const reducer = getReducer("INFORMATION-SYSTEM");
  return reducer(response[0]);  
};

export const findAllInformationSystems = async (args, dbName, dataSources, select ) => {
  const sparqlQuery = selectAllInformationSystemsQuery(select, args);
  let response;
  try {
    response = await dataSources.Stardog.queryAll({
      dbName,
      sparqlQuery,
      queryId: "Select List of Information Systems",
      singularizeSchema: singularizeInformationSystemSchema
    });
  } catch (e) {
    console.log(e)
    throw e
  }

  // no results found
  if (response === undefined || (Array.isArray(response) && response.length === 0)) return null;

  const edges = [];
  const reducer = getReducer("INFORMATION-SYSTEM");
  let skipCount = 0,filterCount = 0, resultCount = 0, limit, offset, limitSize, offsetSize;
  limitSize = limit = (args.first === undefined ? response.length : args.first) ;
  offsetSize = offset = (args.offset === undefined ? 0 : args.offset) ;

  // Determine the security objectives and sensitivity level based on the
  // list of information types, if any, provided or provide appropriate defaults.
  for (let item of response) {
    if (select.includes('risk_count') || select.includes('top_risk_severity')) {
      // add the count of risks associated with this asset
      item.risk_count = (item.related_risks ? item.related_risks.length : 0);
      // determine the highest risk score and severity
      if (item.related_risks !== undefined && item.risk_count > 0) {
        let { highestRiskScore, highestRiskSeverity } = await getOverallRisk(item.related_risks, dbName, dataSources);
        item.risk_score = highestRiskScore || 0;
        item.risk_level = highestRiskSeverity || null;
        item.top_risk_severity = item.risk_level;
      }
    }

    let { confidentiality, integrity, availability } = await computeSecurityObjectives(item.information_types);
    item.security_objective_confidentiality = confidentiality;
    item.security_objective_integrity = integrity;
    item.security_objective_availability = availability;
  
    // Determine the security sensitivity level
    item.security_sensitivity_level = computeSensitivityLevel( confidentiality, 
                                                              integrity, 
                                                              availability );
  
    // if not specified, supply default for privacy designation
    if (item.privacy_designation === undefined) {
      item.privacy_designation = false;
    }

    // if not specified, determine if system is deemed critical
    if (item.critical_system_designation === undefined) {
      item.critical_system_designation = await determineCriticalSystemDesignation(
                                                    item.security_sensitivity_level, 
                                                    item.privacy_designation );
    }
  }

  let resultList ;
  let sortBy;
  if (args.orderedBy !== undefined ) {
    if (args.orderedBy === 'top_risk_severity') {
      sortBy = 'risk_score';
    } else {
      sortBy = args.orderedBy;
    }
    resultList = response.sort(compareValues(sortBy, args.orderMode ));
  } else {
    resultList = response;
  }

  // return null if offset value beyond number of results items
  if (offset > resultList.length) return null;

  // for each result in the result set
  for (let resultItem of resultList) {
    if (resultItem.id === undefined) {
      console.log(`[CYIO] CONSTRAINT-VIOLATION: (${dbName}) ${resultItem.iri} missing field 'id'; skipping`);
      skipCount++;
      continue;
    }

    // skip down past the offset
    if (offset) {
      offset--
      continue
    }

    // filter out non-matching entries if a filter is to be applied
    if ('filters' in args && args.filters != null && args.filters.length > 0) {
      if (!filterValues(resultItem, args.filters, args.filterMode) ) {
        continue
      }
      filterCount++;
    }

    // if haven't reached limit to be returned
    if (limit) {
      let edge = {
        cursor: resultItem.iri,
        node: reducer(resultItem),
      }
      edges.push(edge)
      limit--;
      if (limit === 0) break;
    }
  }
  // check if there is data to be returned
  if (edges.length === 0 ) return null;
  let hasNextPage = false, hasPreviousPage = false;
  resultCount = resultList.length - skipCount;
  if (edges.length < resultCount) {
    if (edges.length === limitSize && filterCount <= limitSize ) {
      hasNextPage = true;
      if (offsetSize > 0) hasPreviousPage = true;
    }
    if (edges.length <= limitSize) {
      if (filterCount !== edges.length) hasNextPage = true;
      if (filterCount > 0 && offsetSize > 0) hasPreviousPage = true;
    }
  }
  return {
    pageInfo: {
      startCursor: edges[0].cursor,
      endCursor: edges[edges.length-1].cursor,
      hasNextPage: (hasNextPage ),
      hasPreviousPage: (hasPreviousPage),
      globalCount: resultCount,
    },
    edges: edges,
  }
};

export const createInformationSystem = async (input, dbName, dataSources, select) => {
  // WORKAROUND to remove input fields with null or empty values so creation will work
  for (const [key, value] of Object.entries(input)) {
    if (Array.isArray(input[key]) && input[key].length === 0) {
      delete input[key];
      continue;
    }
    if (value === null || value.length === 0) {
      delete input[key];
    }
  }
  // END WORKAROUND

  // Compute system ids if not supplied
  if (!input.system_ids && input.system_name) {
    let id_material = {...(input.system_name && {"system_name": input.system_name})};
    input.system_ids = [generateId(id_material, DARKLIGHT_NS)];
  }

  // set the component type to be 'system'
  if (input.component_type === undefined) input.component_type = 'system';

  // if not specified, supply default deployment model
  if (input.deployment_model === undefined) input.deployment_model = [ 'on-premise' ];

  for( let deploy of input.deployment_model) {
    // if deployment model is on-premise, can't specify cloud service model
    if ((input.deployment_model.length === 1 && deploy === 'on-premise') && input.cloud_service_model !== undefined) {
      throw new UserInputError(`cloud service model can only be specified when deployment model specifies some type of cloud`);
    }
    // if a specified deployment model is 'cloud' and service model is not specified, supply default cloud service model
    if ((deploy.includes('cloud') || (deploy === 'other')) && input.cloud_service_model === undefined) {
      input.cloud_service_model = 'saas';
      break;
    }
  }

  // if not specified, supply default for status
  if (input.operational_status === undefined) input.operational_status = 'operational';

  // if not specified, supply default assurance levels
  if (input.identity_assurance_level === undefined) input.identity_assurance_level = 'IAL1';
  if (input.authenticator_assurance_level === undefined) input.authenticator_assurance_level = 'AAL1';
  if (input.federation_assurance_level === undefined) input.federation_assurance_level = 'UNKNOWN';

  // If not specified, supply default objectives impact levels
  let { confidentiality, integrity, availability } = await computeSecurityObjectives(input.information_types);
  if (input.security_objective_confidentiality === undefined) input.security_objective_confidentiality = confidentiality;
  if (input.security_objective_integrity === undefined) input.security_objective_integrity = integrity;
  if (input.security_objective_availability === undefined) input.security_objective_availability = availability;

  // Determine the security sensitivity level
  input.security_sensitivity_level = computeSensitivityLevel( confidentiality, 
                                                              integrity, 
                                                              availability );

  // if not specified, supply default for privacy designation
  if (input.privacy_designation === undefined) {
    input.privacy_designation = false;
  }

  // if not specified, determine if system is deemed critical
  if (input.critical_system_designation === undefined) {
    input.critical_system_designation = await determineCriticalSystemDesignation(
                                                  input.security_sensitivity_level, 
                                                  input.privacy_designation );
  }

  // Need to escape contents, remove explicit newlines, and collapse multiple what spaces.
  if (input.description !== undefined ) {
    input.description = input.description.replace(/\s+/g, ' ')
                                        .replace(/\n/g, '\\n')
                                        .replace(/\"/g, '\\"')
                                        .replace(/\'/g, "\\'")
                                        .replace(/[\u2019\u2019]/g, "\\'")
                                        .replace(/[\u201C\u201D]/g, '\\"');
  }
  if (input.purpose !== undefined) {
    input.purpose = input.purpose.replace(/\s+/g, ' ')
                                  .replace(/\n/g, '\\n')
                                  .replace(/\"/g, '\\"')
                                  .replace(/\'/g, "\\'")
                                  .replace(/[\u2019\u2019]/g, "\\'")
                                  .replace(/[\u201C\u201D]/g, '\\"');
  }

  // Collect all the nested definitions and remove them from input array
  let nestedDefinitions = {
    'information_types': { values: input.information_types, props: {}, objectType: 'information-type', createFunction: createInformationType },
    'authorization_boundary': { values: input.authorization_boundary, props: {}, objectType: 'description-block', createFunction: createDescriptionBlock },
    'network_architecture': { values: input.network_architecture, props: {}, objectType: 'description-block', createFunction: createDescriptionBlock },
    'data_flow': { values: input.data_flow, props: {}, objectType: 'description-block', createFunction: createDescriptionBlock }
  };
	for (let [fieldName, fieldInfo] of Object.entries(nestedDefinitions)) {
    if (fieldInfo.values === undefined || fieldInfo.values === null) continue;
    if (!Array.isArray(fieldInfo.values)) fieldInfo.values = [fieldInfo.values];
    for( let fieldValue of fieldInfo.values) {
      for (let [key, value] of Object.entries(fieldValue)) {
        if (typeof value === 'string') {
          value = value.replace(/\s+/g, ' ')
                        .replace(/\n/g, '\\n')
                        .replace(/\"/g, '\\"')
                        .replace(/\'/g, "\\'")
                        .replace(/[\u2019\u2019]/g, "\\'")
                        .replace(/[\u201C\u201D]/g, '\\"');
        }
        nestedDefinitions[fieldName]['props'][key] = value;
      }
    }
    if (input[fieldName]) delete input[fieldName];
  }

  // Collect all the referenced objects and remove them from input array
  let objectReferences = {
    'responsible_parties': { ids: input.responsible_parties, objectType: 'oscal-responsible-party' },
    'components': { ids: input.system_implementation ? input.system_implementation.components : undefined, objectType: 'component' },
    'inventory_items': { ids: input.system_implementation ? input.system_implementation.inventory_items : undefined, objectType: 'inventory-item' },
    'leveraged_authorizations': { ids: input.system_implementation ? input.system_implementation.leveraged_authorizations : undefined, objectType: 'oscal-leveraged-authorization' },
    'users': { ids: input.system_implementation ? input.system_implementation.users : undefined, objectType: 'oscal-user'}
  };
  if (input.responsible_parties) delete input.responsible_parties;
  if (input.system_implementation) delete input.system_implementation;

  // create the Information System object
  let response;
  let {iri, id, query} = insertInformationSystemQuery(input);
  try {
    response = await dataSources.Stardog.create({
      dbName,
      sparqlQuery: query,
      queryId: "Create Information System object"
      });
  } catch (e) {
    console.log(e)
    throw e
  }

  // Add the Information System to the Asset Inventory
  const invQuery = addToInventoryQuery(iri);
  await dataSources.Stardog.create({
    dbName,
    sparqlQuery: invQuery,
    queryId: 'Add Information System Asset to Inventory',
  });

  // Attach any nest definitions
  for (let [key, value] of Object.entries(nestedDefinitions)) {
		let itemName = value.objectType.replace(/-/g, ' ');
    if (Object.keys(value.props).length !== 0 ) {
      let item;
      try {
        let select = ['id','iri']
        item = await value.createFunction(value.props, dbName, dataSources, select);
      } catch (e) {
        console.log(e)
        throw e
      }

      // attach the definition to the new Information System
      let attachQuery = attachToInformationSystemQuery(id, key, item.iri );
      try {
        response = await dataSources.Stardog.create({
          dbName,
          sparqlQuery: attachQuery,
          queryId: `Attach ${itemName}`
          });
      } catch (e) {
        console.log(e)
        throw e
      }
    }
  }

  // Attach any references to other objects
  for (let [key, value] of Object.entries(objectReferences)) {
    if (value.ids === undefined || value.ids === null) continue;
		let itemName = value.objectType.replace(/-/g, ' ');
    let iris = [];
    for (let refId of value.ids) {
      let sparqlQuery = selectObjectIriByIdQuery(refId, value.objectType);
      let result = await dataSources.Stardog.queryById({
        dbName,
        sparqlQuery,
        queryId: "Obtaining IRI for the object with id",
        singularizeSchema: singularizeInformationSystemSchema
      });
      if (result === undefined || result.length === 0) throw new UserInputError(`Entity does not exist with ID ${refId}`);
      iris.push(`<${result[0].iri}>`);
    }

    if (iris.length > 0) {
      // attach the definition to the new Information System
      let attachQuery = attachToInformationSystemQuery(id, key, iris );
      try {
        response = await dataSources.Stardog.create({
          dbName,
          sparqlQuery: attachQuery,
          queryId: `Attaching one or more ${itemName} to information system`
          });
      } catch (e) {
        console.log(e)
        throw e
      }
    }
  }

  // retrieve the newly created Information System to be returned
  const selectQuery = selectInformationSystemQuery(id, select);
  let result;
  try {
    result = await dataSources.Stardog.queryById({
      dbName,
      sparqlQuery: selectQuery,
      queryId: "Select Information System object",
      singularizeSchema: singularizeInformationSystemSchema
    });
  } catch (e) {
    console.log(e)
    throw e
  }
  if (result === undefined || result === null || result.length === 0) return null;
  const reducer = getReducer("INFORMATION-SYSTEM");
  return reducer(result[0]);
};

export const deleteInformationSystemById = async ( id, dbName, dataSources) => {
  let select = ['iri','id','authorization_boundary','network_architecture','data_flow'];
  let idArray = [];
  if (!Array.isArray(id)) {
    idArray = [id];
  } else {
    idArray = id;
  }

  let removedIds = []
  for (let itemId of idArray) {
    let response;
    if (!checkIfValidUUID(itemId)) throw new UserInputError(`Invalid identifier: ${itemId}`);  

    // check if object with id exists
    let sparqlQuery = selectInformationSystemQuery(itemId, select);
    try {
      response = await dataSources.Stardog.queryById({
        dbName,
        sparqlQuery,
        queryId: "Select Information System",
        singularizeSchema: singularizeInformationSystemSchema
      });
    } catch (e) {
      console.log(e)
      throw e
    }
    
    if (response === undefined || response.length === 0) throw new UserInputError(`Entity does not exist with ID ${itemId}`);
    let infoSys = response[0];

    // Removing Information System Asset from Asset Inventory
    const invQuery = removeFromInventoryQuery(infoSys.iri);
    await dataSources.Stardog.create({
      dbName,
      sparqlQuery: invQuery,
      queryId: 'Removing Information System Asset from Inventory',
    });

    let nestedReferences = {
      'authorization_boundary': { iris: infoSys.authorization_boundary, deleteFunction: deleteDescriptionBlockByIri},
      'network_architecture': { iris: infoSys.network_architecture, deleteFunction: deleteDescriptionBlockByIri},
      'data_flow': { iris: infoSys.data_flow, deleteFunction: deleteDescriptionBlockByIri }
    };
    // delete any nested nodes that are private to the information system
    for (let [fieldName, fieldInfo] of Object.entries(nestedReferences)) {
      if (fieldInfo.iris === undefined || fieldInfo.iris === null) continue;
      if (!Array.isArray(fieldInfo.iris)) fieldInfo.iris = [fieldInfo.iris];
      for( let descBlockIri of fieldInfo.iris) {
        let result = await deleteDescriptionBlockByIri(descBlockIri, dbName, dataSources);
      }
    }
  
    sparqlQuery = deleteInformationSystemQuery(itemId);
    try {
      response = await dataSources.Stardog.delete({
        dbName,
        sparqlQuery,
        queryId: "Delete Information System"
      });
    } catch (e) {
      console.log(e)
      throw e
    }
    
    removedIds.push(itemId);
  }

  if (!Array.isArray(id)) return id;
  return removedIds;
};

export const deleteInformationSystemByIri = async ( iri, dbName, dataSources) => {
    // check if object with iri exists
    let select = ['iri','id','authorization_boundary','network_architecture','data_flow'];
    let response;
    try {
      let sparqlQuery = selectInformationSystemByIriQuery(iri, select);
      response = await dataSources.Stardog.queryById({
        dbName,
        sparqlQuery,
        queryId: "Select Information System",
        singularizeSchema: singularizeInformationSystemSchema
      });
    } catch (e) {
      console.log(e)
      throw e
    }
    
    if (response === undefined || response.length === 0) throw new UserInputError(`Entity does not exist with IRI ${iri}`);
    let infoSys = response[0];

    // Removing Information System Asset from Asset Inventory
    const connectQuery = removeFromInventoryQuery(infoSys.iri);
    await dataSources.Stardog.create({
      dbName,
      sparqlQuery: connectQuery,
      queryId: 'Removing Information System Asset from Inventory',
    });

    let nestedReferences = {
      'authorization_boundary': { iris: infoSys.authorization_boundary, deleteFunction: deleteDescriptionBlockByIri},
      'network_architecture': { iris: infoSys.network_architecture, deleteFunction: deleteDescriptionBlockByIri},
      'data_flow': { iris: infoSys.data_flow, deleteFunction: deleteDescriptionBlockByIri }
    };
  
    // delete any nested nodes private to the information system
    for (let [fieldName, fieldInfo] of Object.entries(nestedDefinitions)) {
      if (fieldInfo.iris === undefined || fieldInfo.iris === null) continue;
      if (!Array.isArray(fieldInfo.iris)) fieldInfo.iris = [fieldInfo.iris];
      for( let descBlockIri of fieldInfo.iris) {
        let result = await deleteDescriptionBlockByIri(descBlockIri, dbName, dataSources);
      }
    }

    sparqlQuery = deleteInformationSystemByIriQuery(iri);
    try {
      response = await dataSources.Stardog.delete({
        dbName,
        sparqlQuery,
        queryId: "Delete Information System"
      });
    } catch (e) {
      console.log(e)
      throw e
    }

  return iri;
};

export const editInformationSystemById = async (id, input, dbName, dataSources, select, schema) => {
  if (!checkIfValidUUID(id)) throw new UserInputError(`Invalid identifier: ${id}`);  

  // make sure there is input data containing what is to be edited
  if (input === undefined || input.length === 0) throw new UserInputError(`No input data was supplied`);

  // WORKAROUND to remove immutable fields
  input = input.filter(element => (element.key !== 'id' && element.key !== 'created' && element.key !== 'modified'));

  // check that the object to be edited exists with the predicates - only get the minimum of data
  let editSelect = ['id','created','modified'];
  for (let editItem of input) {
    editSelect.push(editItem.key);
  }

  const sparqlQuery = selectInformationSystemQuery(id, editSelect );
  let response = await dataSources.Stardog.queryById({
    dbName,
    sparqlQuery,
    queryId: "Select Information System",
    singularizeSchema: singularizeInformationSystemSchema
  });
  if (response.length === 0) throw new UserInputError(`Entity does not exist with ID ${id}`);

  // determine operation, if missing
  for (let editItem of input) {
    if (editItem.operation !== undefined) continue;

    // if value if empty then treat as a remove
    if (editItem.value.length === 0) {
      editItem.operation = 'remove';
      continue;
    }
    if (Array.isArray(editItem.value) && editItem.value[0] === null) throw new UserInputError(`Field "${editItem.key}" has invalid value "null"`);

    if (!response[0].hasOwnProperty(editItem.key)) {
      editItem.operation = 'add';
    } else {
      editItem.operation = 'replace';

      // Set operation to 'skip' if no change in value
      if (response[0][editItem.key] === editItem.value) editItem.operation ='skip';
    }
  }

  // Push an edit to update the modified time of the object
  const timestamp = new Date().toISOString();
  if (!response[0].hasOwnProperty('created')) {
    let update = {key: "created", value:[`${timestamp}`], operation: "add"}
    input.push(update);
  }
  let operation = "replace";
  if (!response[0].hasOwnProperty('modified')) operation = "add";
  let update = {key: "modified", value:[`${timestamp}`], operation: `${operation}`}
  input.push(update);

  // Handle the update to fields that have references to other object instances
  for (let editItem  of input) {
    if (editItem.operation === 'skip') continue;

    let value, fieldType, objectType, objArray, iris=[];
    for (value of editItem.value) {
      switch(editItem.key) {
        case 'deployment_model':
          if (!validateEnumValue(value, 'DeploymentModelType', schema)) throw new UserInputError(`Invalid value "${value}" for field "${editItem.key}".`);
          editItem.value[0] = value.replace(/_/g,'-').toLowerCase();
          fieldType = 'simple';
          break;
        case 'cloud_service_model':
          if (!validateEnumValue(value, 'CloudServiceModelType', schema)) throw new UserInputError(`Invalid value "${value}" for field "${editItem.key}".`);
          editItem.value[0] = value.replace(/_/g,'-').toLowerCase();
          fieldType = 'simple';
          break;
        case 'operational_status':
          if (!validateEnumValue(value, 'OperationalStatus', schema)) throw new UserInputError(`Invalid value "${value}" for field "${editItem.key}".`);
          editItem.value[0] = value.replace(/_/g,'-').toLowerCase();
          fieldType = 'simple';
          break;
        case 'identity_assurance_level':
          if (!validateEnumValue(value, 'IdentityAssuranceLevel', schema)) throw new UserInputError(`Invalid value "${value}" for field "${editItem.key}".`);
          editItem.value[0] = value.replace(/_/g,'-');
          fieldType = 'simple';
          break;
        case 'authenticator_assurance_level':
          if (!validateEnumValue(value, 'AuthenticatorAssuranceLevel', schema)) throw new UserInputError(`Invalid value "${value}" for field "${editItem.key}".`);
          editItem.value[0] = value.replace(/_/g,'-');
          fieldType = 'simple';
          break;
        case 'federation_assurance_level':
          if (!validateEnumValue(value, 'FederationAssuranceLevel', schema)) throw new UserInputError(`Invalid value "${value}" for field "${editItem.key}".`);
          editItem.value[0] = value.replace(/_/g,'-');
          fieldType = 'simple';
          break;
        case 'security_objective_confidentiality':
          if (!validateEnumValue(value, 'FIPS199', schema)) throw new UserInputError(`Invalid value "${value}" for field "${editItem.key}".`);
          editItem.value[0] = value.replace(/_/g,'-').toLowerCase();
          fieldType = 'simple';
          break;
        case 'security_objective_integrity':
          if (!validateEnumValue(value, 'FIPS199', schema)) throw new UserInputError(`Invalid value "${value}" for field "${editItem.key}".`);
          editItem.value[0] = value.replace(/_/g,'-').toLowerCase();
          fieldType = 'simple';
          break;
        case 'security_objective_availability':
          if (!validateEnumValue(value, 'FIPS199', schema)) throw new UserInputError(`Invalid value "${value}" for field "${editItem.key}".`);
          editItem.value[0] = value.replace(/_/g,'-').toLowerCase();
          fieldType = 'simple';
          break;
        case 'responsible_parties':
          objectType = 'oscal-responsible-party';
          fieldType = 'id';
          break;
        case 'labels':
          objectType = 'label';
          fieldType = 'id';
          break;
        case 'links':
          objectType = 'external-reference';
          fieldType = 'id';
          break;
        case 'remarks':
          objectType = 'note';
          fieldType = 'id';
          break;
        case 'security_sensitivity_level':
        case 'information_types':
        case 'system_implementation':
        case 'authorization_boundary':
        case 'network_architecture':
        case 'data_flow':
          throw new UserInputError(`Cannot directly edit field "${editItem.key}".`);
        default:
          fieldType = 'simple';
          break;
      }

      if (fieldType === 'id') {
        // continue to next item if nothing to do
        if (editItem.operation === 'skip') continue;

        let sparqlQuery = selectObjectIriByIdQuery(value, objectType);
        let result = await dataSources.Stardog.queryById({
          dbName,
          sparqlQuery,
          queryId: "Obtaining IRI for the object with id",
          singularizeSchema: singularizeInformationSystemSchema
        });
        if (result === undefined || result.length === 0) throw new UserInputError(`Entity does not exist with ID ${value}`);
        iris.push(`<${result[0].iri}>`);
      }
    }
    if (iris.length > 0) editItem.value = iris;
  }    

  const query = updateQuery(
    `http://cyio.darklight.ai/information-system--${id}`,
    "http://csrc.nist.gov/ns/oscal/info-system#InformationSystem",
    input,
    informationSystemPredicateMap
  );
  if (query !== null) {
    let response;
    try {
      response = await dataSources.Stardog.edit({
        dbName,
        sparqlQuery: query,
        queryId: "Update Information System"
      });  
    } catch (e) {
      console.log(e)
      throw e
    }
  }

  const selectQuery = selectInformationSystemQuery(id, select);
  const result = await dataSources.Stardog.queryById({
    dbName,
    sparqlQuery: selectQuery,
    queryId: "Select Information System",
    singularizeSchema: singularizeInformationSystemSchema
  });
  const reducer = getReducer("INFORMATION-SYSTEM");
  return reducer(result[0]);
};

export const attachToInformationSystem = async (id, field, entityId, dbName, dataSources) => {
  let sparqlQuery;
  if (!checkIfValidUUID(id)) throw new UserInputError(`Invalid identifier: ${id}`);
  if (!checkIfValidUUID(entityId)) throw new UserInputError(`Invalid identifier: ${entityId}`);

  // check to see if the information system exists
  let iri = `<http://cyio.darklight.ai/information-system--${id}>`;
  sparqlQuery = selectInformationSystemByIriQuery(iri, select);
  let response;
  try {
    response = await dataSources.Stardog.queryById({
      dbName,
      sparqlQuery,
      queryId: "Select Information System",
      singularizeSchema: singularizeInformationSystemSchema
    });
  } catch (e) {
    console.log(e)
    throw e
  }
  if (response === undefined || response === null || response.length === 0) throw new UserInputError(`Entity does not exist with ID ${id}`);

  let attachableObjects = {
    'information_types': 'information-type',
    'authorization_boundary': 'description-block',
    'network_architecture': 'description-block',
    'data_flow': 'description-block',
    'responsible_parties': 'oscal-responsible-party',
    'labels': 'label',
    'links': 'link',
    'remarks': 'remark',
    // internal fields
    'components': 'component',
    'inventory_items': 'inventory-item',
    'leveraged_authorizations': 'oscal-leveraged-authorization',
    'users': 'oscal-user',
  }
  let objectType = attachableObjects[field];
  try {
    // check to see if the entity exists
    sparqlQuery = selectObjectIriByIdQuery(entityId, objectType);
    response = await dataSources.Stardog.queryById({
      dbName,
      sparqlQuery,
      queryId: "Obtaining IRI for the object with id",
      singularizeSchema: singularizeInformationSystemSchema
    });
  } catch (e) {
    console.log(e)
    throw e
  }
  if (response === undefined || response === null || response.length === 0) throw new UserInputError(`Entity does not exist with ID ${entityId}`);
  
  // check to make sure entity to be attached is proper for the field specified
  if (response[0].object_type !== attachableObjects[field]) throw new UserInputError(`Can not attach object of type '${response[0].object_type}' to field '${field}'`);

  // retrieve the IRI of the entity
  let entityIri = `<${response[0].iri}>`;

  // Attach the object to the information system
  sparqlQuery = attachToInformationSystemQuery(id, field, entityIri);
  try {
    response = await dataSources.Stardog.create({
      dbName,
      sparqlQuery,
      queryId: `Attach ${field} to Information System`
      });
  } catch (e) {
    console.log(e)
    throw e
  }

  return true;
};

export const detachFromInformationSystem = async (id, field, entityId, dbName, dataSources) => {
  let sparqlQuery;
  if (!checkIfValidUUID(id)) throw new UserInputError(`Invalid identifier: ${id}`);
  if (!checkIfValidUUID(entityId)) throw new UserInputError(`Invalid identifier: ${entityId}`);

  // check to see if the information system exists
  let iri = `<http://cyio.darklight.ai/information-system--${id}>`;
  sparqlQuery = selectInformationSystemByIriQuery(iri, select);
  let response;
  try {
    response = await dataSources.Stardog.queryById({
      dbName,
      sparqlQuery,
      queryId: "Select Information System",
      singularizeSchema: singularizeInformationSystemSchema
    });
  } catch (e) {
    console.log(e)
    throw e
  }
  if (response === undefined || response === null || response.length === 0) throw new UserInputError(`Entity does not exist with ID ${id}`);

  let attachableObjects = {
    'information_types': 'information-type',
    'authorization_boundary': 'description-block',
    'network_architecture': 'description-block',
    'data_flow': 'description-block',
    'responsible_parties': 'oscal-responsible-party',
    'labels': 'label',
    'links': 'link',
    'remarks': 'remark',
    // internal fields
    'components': 'component',
    'inventory_items': 'inventory-item',
    'leveraged_authorizations': 'oscal-leveraged-authorization',
    'users': 'oscal-user',
  }
  let objectType = attachableObjects[field];
  try {
    // check to see if the entity exists
    sparqlQuery = selectObjectIriByIdQuery(entityId, objectType);
    response = await dataSources.Stardog.queryById({
      dbName,
      sparqlQuery,
      queryId: "Obtaining IRI for the object with id",
      singularizeSchema: singularizeInformationSystemSchema
    });
  } catch (e) {
    console.log(e)
    throw e
  }
  if (response === undefined || response === null || response.length === 0) throw new UserInputError(`Entity does not exist with ID ${entityId}`);

  // check to make sure entity to be attached is proper for the field specified
  if (response[0].object_type !== attachableObjects[field]) throw new UserInputError(`Can not attach object of type '${response[0].object_type}' to field '${field}'`);

  // retrieve the IRI of the entity
  let entityIri = `<${response[0].iri}>`;

  // Attach the object to the information system
  sparqlQuery = detachFromInformationSystemQuery(id, field, entityIri);
  try {
    response = await dataSources.Stardog.create({
      dbName,
      sparqlQuery,
      queryId: `Detach ${field} from Information System`
      });
  } catch (e) {
    console.log(e)
    throw e
  }

  return true;
};

export const getInformationSystemSecurityStatus = async (id, dbName, dataSources, select) => {
  let sparqlQuery;
  if (!checkIfValidUUID(id)) throw new UserInputError(`Invalid identifier: ${id}`);

  // check to see if the information system exists
  let iri = `<http://cyio.darklight.ai/information-system--${id}>`;
  sparqlQuery = selectInformationSystemByIriQuery(iri, select);
  let response;
  try {
    response = await dataSources.Stardog.queryById({
      dbName,
      sparqlQuery,
      queryId: "Select Information System",
      singularizeSchema: singularizeInformationSystemSchema
    });
  } catch (e) {
    console.log(e)
    throw e
  }
  if (response === undefined || response === null || response.length === 0) throw new UserInputError(`Entity does not exist with ID ${id}`);
  return response[0];
};

export const addImplementationEntity = async( id, implementationType, entityId, dbName, dataSources) => {
  if (!checkIfValidUUID(id)) throw new UserInputError(`Invalid identifier: ${id}`);
  if (!checkIfValidUUID(entityId)) throw new UserInputError(`Invalid identifier: ${entityId}`);

  let field;
  switch(implementationType) {
    case 'component':
      field = 'components';
      break;
    case 'inventory_item':
      field = 'inventory_items';
      break;
    case 'leveraged_authorization':
      field = 'leveraged_authorizations';
      break;
    case 'user_type':
      field = 'users';
      break;
    default:
      throw new UserInputError(`Unknown implementation type '${implementationType}'`);      
  }

  let result = await attachToInformationSystem(id, field, entityId, dbName, dataSources);
  return result;
}

export const removeImplementationEntity = async( id, implementationType, entityId, dbName, dataSources) => {
  if (!checkIfValidUUID(id)) throw new UserInputError(`Invalid identifier: ${id}`);
  if (!checkIfValidUUID(entityId)) throw new UserInputError(`Invalid identifier: ${entityId}`);

  let field;
  switch(implementationType) {
    case 'component':
      field = 'components';
      break;
    case 'inventory_item':
      field = 'inventory_items';
      break;
    case 'leveraged_authorization':
      field = 'leveraged_authorizations';
      break;
    case 'user_type':
      field = 'users';
      break;
    default:
      throw new UserInputError(`Unknown implementation type '${implementationType}'`);      
  }

  let result = await detachFromInformationSystem(id, field, entityId, dbName, dataSources);
  return result;
}

// Helper Routines
export const computeSensitivityLevel = ( confidentiality, integrity, availability ) => {
  let sensitivityLevel = 'fips-199-low';
  if ( confidentiality === 'fips-199-moderate' ||
       integrity === 'fips-199-moderate' ||
       availability === 'fips-199-moderate' ) sensitivityLevel = 'fips-199-moderate';
  if ( confidentiality === 'fips-199-high' ||
       integrity === 'fips-199-high' ||
       availability === 'fips-199-high' ) sensitivityLevel = 'fips-199-high';
  return sensitivityLevel;
};

export const computeSecurityObjectives = async ( infoTypes ) => {
  let confidentiality = 'fips-199-low';
  let integrity = 'fips-199-low';
  let availability = 'fips-199-low';

  if (infoTypes === undefined || infoTypes === null) {
    confidentiality = conf.get('app:config:default_confidentiality_impact_level') || 'fips-199-low';
    integrity = conf.get('app:config:default_integrity_impact_level') || 'fips-199-low';
    availability = conf.get('app:config:default_availability_impact_level') || 'fips-199-low';
    return { confidentiality, integrity, availability }
  }

  // if infoTypes is an array of IRIs
  if (typeof infoTypes[0] === 'string' && infoTypes[0].includes('information-types--')) {
    let results = [];
    // retrieve the minimal data required to compute security objectives
    for (let item of response[0].information_types) {
      let result = await findInformationTypeByIri(item.iri, dbName, dataSources, null);
      let infoType = {
        confidentiality_impact: {
          base_impact_level: result.confidentiality_base_impact_level,
          selected_impact_level: result.confidentiality_selected_impact_level
        },
        integrity_impact: {
          base_impact_level: result.integrity_base_impact_level,
          selected_impact_level: result.integrity_selected_impact_level
        },
        availability_impact: {
          base_impact_level: result.availability_base_impact_level,
          selected_impact_level: result.availability_selected_impact_level
        }
      }
      results.push(infoType);
    }
    infoTypes = results;
  }

  for (let infoType of infoTypes) {
    // process confidentiality impact
    if (impactIsGreater(confidentiality, infoType.confidentiality_impact.base_impact_level))
      confidentiality = infoType.confidentiality_impact.base_impact_level;
    if (infoType.confidentiality_impact.selected_impact_level !== undefined) {
      if (impactIsGreater(confidentiality, infoType.confidentiality_impact.selected_impact_level))
      confidentiality = infoType.confidentiality_impact.selected_impact_level;
    }

    // process integrity impact
    if (impactIsGreater(integrity, infoType.integrity_impact.base_impact_level))
      integrity = infoType.integrity_impact.base_impact_level;
    if (infoType.integrity_impact.selected_impact_level !== undefined) {
      if (impactIsGreater(integrity, infoType.integrity_impact.selected_impact_level))
      integrity = infoType.integrity_impact.selected_impact_level;
    }

    // process availability impact
    if (impactIsGreater(availability, infoType.availability_impact.base_impact_level))
      availability = infoType.availability_impact.base_impact_level;
    if (infoType.availability_impact.selected_impact_level !== undefined) {
      if (impactIsGreater(availability, infoType.availability_impact.selected_impact_level))
      availability = infoType.availability_impact.selected_impact_level;
    }
  }

  return { confidentiality, integrity, availability }
};

export const determineCriticalSystemDesignation = async (security_sensitivity_level, privacy_designation) => {
  let minSensitivityLevel = conf.get('app:config:critical.min_sensitivity_level') || 'fips-199-moderate';
  let minPrivacyDesignation = conf.get('app.config.critical.min_privacy_designation') || false;
  if ( impactIsGreater(minSensitivityLevel, security_sensitivity_level)) return true;
  if( security_sensitivity_level === minSensitivityLevel && privacy_designation === minPrivacyDesignation ) return true;
  return false;
};

export const impactIsGreater = ( current, latest ) => {
  if (current === 'fips-199-low' && latest !== 'fips-199-low') return true; // latest is moderate or high
  if (current === 'fips-199-moderate' && latest === 'fips-199-high') return true; // latest is high
  return false;
};

export const findSystemImplementation = async ( parent, dbName, dataSources, selectMap ) => {
  let systemImplementation = {};
  let select = selectMap.getNode('system_implementation')

  if (select.includes('components') && parent.component_iris) {
    let select = selectMap.getNode('components');
    let results = [];
    for (let iri of parent.component_iris) {
      let result = await findComponentByIri(iri, dbName, dataSources, select);
      if (result === undefined || result === null) continue;
      results.push(result);
    }
    if (results.length !== 0) systemImplementation['components'] = results || [];
  }
  if (select.includes('inventory_items') && parent.inventory_item_iris) {
    let select = selectMap.getNode('inventory_items');
    let results = [];
    for (let iri of parent.inventory_item_iris) {
      let result = await findInventoryItemByIri(iri, dbName, dataSources, select);
      if (result === undefined || result === null) continue;
      results.push(result);
    }
    if (results.length !== 0) systemImplementation['inventory_items'] = results || [];
  }
  if (select.includes('leveraged_authorizations') && parent.leveraged_authorization_iris) {
    let select = selectMap.getNode('leveraged_authorizations');
    let results = [];
    for (let iri of parent.leveraged_authorization_iris) {
      let result = await findLeveragedAuthorizationByIri(iri, dbName, dataSources, select);
      if (result === undefined || result === null) continue;
      results.push(result);
    }
    if (results.length !== 0) systemImplementation['leveraged_authorizations'] = results || [];
  }
  if (select.includes('users') && parent.user_iris) {
    let select = selectMap.getNode('users');
    let results = [];
    for (let iri of parent.user_iris) {
      let result = await findUserTypeByIri(iri, dbName, dataSources, select);
      if (result === undefined || result === null) continue;
      results.push(result);
    }
    if (results.length !== 0) systemImplementation['users'] = results || [];
  }

  return systemImplementation;
}

