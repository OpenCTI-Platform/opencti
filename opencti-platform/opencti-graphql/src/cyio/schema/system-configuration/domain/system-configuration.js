import { UserInputError } from 'apollo-server-express';
import { compareValues, filterValues, updateQuery, checkIfValidUUID, CyioError } from '../../utils.js';
import conf from '../../../../config/conf';
import { selectObjectIriByIdQuery } from '../../global/global-utils.js';
import {
  attachToSystemConfigurationQuery,
  detachFromSystemConfigurationQuery,
  singularizeSystemConfigurationSchema,
} from '../schema/sparql/system-configuration.js';


export const attachToSystemConfiguration = async (entryId, type, dataSources) => {
  let contextDB = conf.get('app:database:context') || 'cyber-context';
  if (!checkIfValidUUID(entryId)) throw new CyioError(`Invalid identifier: ${entryId}`);

  // check to see if they entity to be attached exists
  let sparqlQuery = selectObjectIriByIdQuery(entryId, type);
  let result = await dataSources.Stardog.queryById({
    dbName: contextDB,
    sparqlQuery,
    queryId: "Obtaining IRI for object with id to attached",
    singularizeSchema: singularizeSystemConfigurationSchema
  });
  if (result === undefined || result.length === 0) throw new CyioError(`Entity does not exist with ID ${entryId}`);
  let iris = `<${result[0].iri}>`;

  // determine the field based on the type of data to be attached
  let field;
  switch(type) {
    case 'information-type-catalog':
      field = 'information_type_catalogs';
      break;
    case 'settings':
      field = 'settings';
      break;
    case 'marking-definition':
      field = 'data_markings';
      break;
    case 'data-source':
      field = 'data_sources';
      break;
    case 'organization':
      field = 'organizations';
      break;
    case 'themes':
      field = 'themes';
      break;
    case 'workspace':
      field = 'workspaces';
      break;
    default:
      throw new CyioError(`Unknown type ${type}`);
  } 

  // attach the entity to the Information Type Catalog instance
  let configDB = conf.get('app:database:config') || 'cyio-config';
  let configId = 'cba750df-94f8-5dc5-a671-ff104435d566';
  sparqlQuery = attachToSystemConfigurationQuery(configId, field, iris);
  try {
    await dataSources.Stardog.create({
      dbName: configDB,
      sparqlQuery,
      queryId: 'Attaching to entity to System Configuration',
    });  
  } catch (e) {
    console.log(e)
    return false;
  }

  return true;
}

export const detachFromSystemConfiguration = async (entryId, type, dataSources) => {
  let contextDB = conf.get('app:database:context') || 'cyber-context';
  if (!checkIfValidUUID(entryId)) throw new CyioError(`Invalid identifier: ${entryId}`);

  // check to see if they entity to be attached exists
  let sparqlQuery = selectObjectIriByIdQuery(entryId, type);
  let result = await dataSources.Stardog.queryById({
    dbName: contextDB,
    sparqlQuery,
    queryId: "Obtaining IRI for object with id to detached",
    singularizeSchema: singularizeSystemConfigurationSchema
  });
  if (result === undefined || result.length === 0) throw new CyioError(`Entity does not exist with ID ${entryId}`);
  let iris = `<${result[0].iri}>`;

  // determine the field based on the type of data to be attached
  let field;
  switch(type) {
    case 'information-type-catalog':
      field = 'information_type_catalogs';
      break;
    case 'settings':
      field = 'settings';
      break;
    case 'marking-definition':
      field = 'data_markings';
      break;
    case 'data-source':
      field = 'data_sources';
      break;
    case 'organization':
      field = 'organizations';
      break;
    case 'themes':
      field = 'themes';
      break;
    case 'workspace':
      field = 'workspaces';
      break;
    default:
      throw new CyioError(`Unknown type ${type}`);
  } 

  // detach the entity to the Information Type Catalog instance
  let configDB = conf.get('app:database:config') || 'cyio-config';
  let configId = 'cba750df-94f8-5dc5-a671-ff104435d566';
  sparqlQuery = detachFromSystemConfigurationQuery(configId, field, iris);
  try {
    await dataSources.Stardog.delete({
      dbName: configDB,
      sparqlQuery,
      queryId: 'Detaching entity from System Configuration',
    });  
  } catch (e) {
    console.log(e)
    return false;
  }

  return true;
}
