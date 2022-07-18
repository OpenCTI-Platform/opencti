import { riskSingularizeSchema as singularizeSchema } from '../../risk-mappings.js';
import { compareValues, updateQuery, filterValues } from '../../../utils.js';
import { UserInputError } from "apollo-server-express";
import {
  selectLabelByIriQuery,
  selectExternalReferenceByIriQuery,
  selectNoteByIriQuery,
  getReducer as getGlobalReducer,
} from '../../../global/resolvers/sparql-query.js';
import {
  attachToPOAMQuery,
  detachFromPOAMQuery,
} from '../../poam/resolvers/sparql-query.js';
import {
  getReducer,
  insertResponsibleRoleQuery,
  selectResponsibleRoleQuery,
  selectAllResponsibleRoles,
  deleteResponsibleRoleQuery,
  attachToResponsibleRoleQuery,
  selectRoleByIriQuery,  
  responsiblePartyPredicateMap,
} from './sparql-query.js';

const responsibleRoleResolvers = {
  Query: {
    oscalResponsibleRoles: async (_, args, { dbName, dataSources, selectMap }) => {
      const edges = [];
      const reducer = getReducer("RESPONSIBLE-ROLE");
      const sparqlQuery = selectAllResponsibleRoles(selectMap.getNode("node"), args);
      let response;
      try {
        response = await dataSources.Stardog.queryAll({
          dbName,
          sparqlQuery,
          queryId: "Select List of Responsible Roles",
          singularizeSchema
        });
      } catch (e) {
        console.log(e)
        throw e
      }
      if (response === undefined) return null;

      // Handle reporting Stardog Error
      if (typeof (response) === 'object' && 'body' in response) {
        throw new UserInputError(response.statusText, {
            error_details: (response.body.message ? response.body.message : response.body),
            error_code: (response.body.code ? response.body.code : 'N/A')
        });
      }
        
      let filterCount, resultCount, limit, offset, limitSize, offsetSize;
      limitSize = limit = (args.first === undefined ? response.length : args.first) ;
      offsetSize = offset = (args.offset === undefined ? 0 : args.offset) ;
      filterCount = 0;
      let respRoleList;
      if (args.orderedBy !== undefined) {
        respRoleList = response.sort(compareValues(args.orderedBy, args.orderMode));
      } else {
        respRoleList = response;
      }

      if (offset > respRoleList.length) return null;
      resultCount = respRoleList.length;
      for (let respRole of respRoleList) {
        if (offset) {
          offset--
          continue
        }

        // if props were requested
        if (selectMap.getNode('node').includes('props')) {
          let props = convertToProperties(respRole, responsiblePartyPredicateMap);
          if (props !== null) respRole.props = props;
        }

        // filter out non-matching entries if a filter is to be applied
        if ('filters' in args && args.filters != null && args.filters.length > 0) {
          if (!filterValues(respRole, args.filters, args.filterMode)) {
            continue
          }
          filterCount++;
        }

        // if haven't reached limit to be returned
        if (limit) {
          let edge = {
            cursor: respRole.iri,
            node: reducer(respRole),
          }
          edges.push(edge)
          limit--;
          if (limit === 0) break;
        }
      }

      // check if there is data to be returned
      if (edges.length === 0 ) return null;
      let hasNextPage = false, hasPreviousPage = false;
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
    },
    oscalResponsibleRole: async (_, { id }, { dbName, dataSources, selectMap }) => {
      const sparqlQuery = selectResponsibleRoleQuery(id, selectMap.getNode("oscalResponsibleRole"));
      let response;
      try {
        response = await dataSources.Stardog.queryById({
          dbName,
          sparqlQuery,
          queryId: "Select OSCAL Responsible Party",
          singularizeSchema
        });
      } catch (e) {
        console.log(e)
        throw e
      }

      // Handle reporting Stardog Error
      if (typeof (response) === 'object' && 'body' in response) {
        throw new UserInputError(response.statusText, {
          error_details: (response.body.message ? response.body.message : response.body),
          error_code: (response.body.code ? response.body.code : 'N/A')
        });
      }

      if (response === undefined) return null;
      const reducer = getReducer("RESPONSIBLE-ROLE");
      let respRole = response[0];

      // if props were requested
      if (selectMap.getNode('oscalResponsibleRole').includes('props')) {
        let props = convertToProperties(respRole, responsiblePartyPredicateMap);
        if (props !== null) respRole.props = props;
      }

      return reducer(respRole);
    }
  },
  Mutation: {
    createOscalResponsibleRole: async (_, { input }, { dbName, selectMap, dataSources }) => {
      // TODO: WORKAROUND to remove input fields with null or empty values so creation will work
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

      // Setup to handle embedded objects to be created
      let parties, role;
      if (input.parties !== undefined) {
        parties = input.parties;
      }
      if (input.role !== undefined) {
        role = input.role;
      }

      // create the Responsible Party
      const { iri, id, query } = insertResponsibleRoleQuery(input);
      await dataSources.Stardog.create({
        dbName,
        sparqlQuery: query,
        queryId: "Create OSCAL Responsible Role"
      });

      // add the responsible role to the parent object (if supplied)
      // TODO: WORKAROUND attach the responsible role to the default POAM until Metadata object is supported
      const poamId = "22f2ad37-4f07-5182-bf4e-59ea197a73dc";
      const attachQuery = attachToPOAMQuery(poamId, 'responsible_parties', iri );
      try {
        await dataSources.Stardog.create({
          dbName,
          queryId: "Add ResponsibleRole to POAM",
          sparqlQuery: attachQuery
        });
      } catch (e) {
        console.log(e)
        throw e
      }
      // END WORKAROUND

      // attach associated Role
      if (role !== undefined && role !== null) {
        const roleIris = [];
        roleIris.push(`<http://csrc.nist.gov/ns/oscal/common#Role-${role}>`);

        // attach the Role to the Responsible Role
        const roleAttachQuery = attachToResponsibleRoleQuery(id, 'role', roleIris);
        await dataSources.Stardog.create({
          dbName,
          sparqlQuery: roleAttachQuery,
          queryId: "Attach reference to the Role to this Responsible Role"
        });        
      }
      // attach any Parties
      if (parties !== undefined && parties !== null) {
        const partyIris = [];
        for (let partyIri of parties) partyIris.push(`<http://csrc.nist.gov/ns/oscal/common#Party-${partyIri}>`);

        // attach the Party to the Responsible Role
        const partyAttachQuery = attachToResponsibleRoleQuery(id, 'parties', partyIris);
        await dataSources.Stardog.create({
          dbName,
          sparqlQuery: partyAttachQuery,
          queryId: "Attach references to one or more Parties to this Responsible Role"
        });        
      }

      // retrieve information about the newly created Responsible Role to return to the user
      const select = selectResponsibleRoleQuery(id, selectMap.getNode("createOscalResponsibleRole"));
      let response;
      try {
        response = await dataSources.Stardog.queryById({
          dbName,
          sparqlQuery: select,
          queryId: "Select OSCAL Responsible Role",
          singularizeSchema
        });
      } catch (e) {
        console.log(e)
        throw e
      }
      const reducer = getReducer("RESPONSIBLE-ROLE");
      return reducer(response[0]);
    },
    deleteOscalResponsibleRole: async (_, { id }, { dbName, dataSources }) => {
      // check that the Role exists
      const sparqlQuery = selectResponsibleRoleQuery(id, null);
      let response;
      try {
        response = await dataSources.Stardog.queryById({
          dbName,
          sparqlQuery,
          queryId: "Select OSCAL Responsible Role",
          singularizeSchema
        });
      } catch (e) {
        console.log(e)
        throw e
      }
      if (response.length === 0) throw new UserInputError(`Entity does not exist with ID ${id}`);
      const reducer = getReducer("RESPONSIBLE-ROLE");
      const responsibleRole = (reducer(response[0]));

      // detach the Responsible Role from the parent object (if supplied)
      // TODO: WORKAROUND attach the responsible role to the default POAM until Metadata object is supported
      const poamId = "22f2ad37-4f07-5182-bf4e-59ea197a73dc";
      const detachQuery = detachFromPOAMQuery(poamId, 'responsible_parties', responsibleRole.iri );
      try {
        await dataSources.Stardog.create({
          dbName,
          queryId: "Detaching Responsible Role from POAM",
          sparqlQuery: detachQuery
        });
      } catch (e) {
        console.log(e)
        throw e
      }
      // END WORKAROUND

      //TODO: Determine any external attachments that will need to be removed when this object is deleted

      // Delete the responsible Role itself
      const query = deleteResponsibleRoleQuery(id);
      try {
        await dataSources.Stardog.delete({
          dbName,
          sparqlQuery: query,
          queryId: "Delete OSCAL Responsible Role"
        });
      } catch (e) {
        console.log(e)
        throw e
      }
      return id;
    },
    editOscalResponsibleRole: async (_, { id, input }, { dbName, dataSources, selectMap }) => {
      // check that the object to be edited exists with the predicates - only get the minimum of data
      let editSelect = ['id'];
      for (let editItem of input) {
        editSelect.push(editItem.key);
      }
      const sparqlQuery = selectResponsibleRoleQuery(id, editSelect );
      let response = await dataSources.Stardog.queryById({
        dbName,
        sparqlQuery,
        queryId: "Select Responsible Role",
        singularizeSchema
      })
      if (response.length === 0) throw new UserInputError(`Entity does not exist with ID ${id}`);

      // TODO: WORKAROUND to handle UI where it DOES NOT provide an explicit operation
      for (let editItem of input) {
        if (!response[0].hasOwnProperty(editItem.key)) editItem.operation = 'add';
      }
      // END WORKAROUND

      const query = updateQuery(
        `http://csrc.nist.gov/ns/oscal/common#ResponsibleRole-${id}`,
        "http://csrc.nist.gov/ns/oscal/common#ResponsibleRole",
        input,
        responsiblePartyPredicateMap
      )
      await dataSources.Stardog.edit({
        dbName,
        sparqlQuery: query,
        queryId: "Update OSCAL Responsible Role"
      });
      const select = selectResponsibleRoleQuery(id, selectMap.getNode("editOscalResponsibleRole"));
      const result = await dataSources.Stardog.queryById({
        dbName,
        sparqlQuery: select,
        queryId: "Select OSCAL Responsible Role",
        singularizeSchema
      });
      const reducer = getReducer("RESPONSIBLE-ROLE");
      return reducer(result[0]);
    },
  },
  OscalResponsibleRole: {
    labels: async (parent, _, {dbName, dataSources, selectMap}) => {
      if (parent.labels_iri === undefined) return [];
      let iriArray = parent.labels_iri;
      const results = [];
      if (Array.isArray(iriArray) && iriArray.length > 0) {
        const reducer = getGlobalReducer("LABEL");
        for (let iri of iriArray) {
          if (iri === undefined || !iri.includes('Label')) continue;
          const sparqlQuery = selectLabelByIriQuery(iri, selectMap.getNode("labels"));
          let response;
          try {
            response = await dataSources.Stardog.queryById({
              dbName,
              sparqlQuery,
              queryId: "Select Label",
              singularizeSchema
            });
          } catch (e) {
            console.log(e)
            throw e
          }
          if (response === undefined) return [];
          if (Array.isArray(response) && response.length > 0) {
            results.push(reducer(response[0]))
          }
          else {
            // Handle reporting Stardog Error
            if (typeof (response) === 'object' && 'body' in response) {
              throw new UserInputError(response.statusText, {
                error_details: (response.body.message ? response.body.message : response.body),
                error_code: (response.body.code ? response.body.code : 'N/A')
              });
            }
          }  
        }
        return results;
      } else {
        return [];
      }
    },
    links: async (parent, _, {dbName, dataSources, selectMap}) => {
      if (parent.links_iri === undefined) return [];
      let iriArray = parent.links_iri;
      const results = [];
      if (Array.isArray(iriArray) && iriArray.length > 0) {
        const reducer = getGlobalReducer("EXTERNAL-REFERENCE");
        for (let iri of iriArray) {
          if (iri === undefined || !iri.includes('ExternalReference')) continue;
          const sparqlQuery = selectExternalReferenceByIriQuery(iri, selectMap.getNode("links"));
          let response;
          try {
            response = await dataSources.Stardog.queryById({
              dbName,
              sparqlQuery,
              queryId: "Select External Reference",
              singularizeSchema
            });
          } catch (e) {
            console.log(e)
            throw e
          }
          if (response === undefined) return [];
          if (Array.isArray(response) && response.length > 0) {
            results.push(reducer(response[0]))
          }
          else {
            // Handle reporting Stardog Error
            if (typeof (response) === 'object' && 'body' in response) {
              throw new UserInputError(response.statusText, {
                error_details: (response.body.message ? response.body.message : response.body),
                error_code: (response.body.code ? response.body.code : 'N/A')
              });
            }
          }  
        }
        return results;
      } else {
        return [];
      }
    },
    remarks: async (parent, _, {dbName, dataSources, selectMap}) => {
      if (parent.remarks_iri === undefined) return [];
      let iriArray = parent.remarks_iri;
      const results = [];
      if (Array.isArray(iriArray) && iriArray.length > 0) {
        const reducer = getGlobalReducer("NOTE");
        for (let iri of iriArray) {
          if (iri === undefined || !iri.includes('Note')) continue;
          const sparqlQuery = selectNoteByIriQuery(iri, selectMap.getNode("remarks"));
          let response;
          try {
            response = await dataSources.Stardog.queryById({
              dbName,
              sparqlQuery,
              queryId: "Select Note",
              singularizeSchema
            });
          } catch (e) {
            console.log(e)
            throw e
          }
          if (response === undefined) return [];
          if (Array.isArray(response) && response.length > 0) {
            results.push(reducer(response[0]))
          }
          else {
            // Handle reporting Stardog Error
            if (typeof (response) === 'object' && 'body' in response) {
              throw new UserInputError(response.statusText, {
                error_details: (response.body.message ? response.body.message : response.body),
                error_code: (response.body.code ? response.body.code : 'N/A')
              });
            }
          }  
        }
        return results;
      } else {
        return [];
      }
    },
    parties: async (parent, _, {dbName, dataSources, selectMap}) => {
      if (parent.parties_iri === undefined) return [];
      let iriArray = parent.parties_iri;
      const results = [];
      if (Array.isArray(iriArray) && iriArray.length > 0) {
        const reducer = getReducer("PARTY");
        for (let iri of iriArray) {
          if (iri === undefined || !iri.includes('Party')) continue;
          const sparqlQuery = selectPartyByIriQuery(iri, selectMap.getNode("parties"));
          let response;
          try {
            response = await dataSources.Stardog.queryById({
              dbName,
              sparqlQuery,
              queryId: "Select Party",
              singularizeSchema
            });
          } catch (e) {
            console.log(e)
            throw e
          }
          if (response === undefined) return [];
          if (Array.isArray(response) && response.length > 0) {
            results.push(reducer(response[0]))
          }
          else {
            // Handle reporting Stardog Error
            if (typeof (response) === 'object' && 'body' in response) {
              throw new UserInputError(response.statusText, {
                error_details: (response.body.message ? response.body.message : response.body),
                error_code: (response.body.code ? response.body.code : 'N/A')
              });
            }
          }  
        }
        return results;
      } else {
        return [];
      }
    },
    role: async (parent, _, {dbName, dataSources, selectMap}) => {
      if (parent.role_iri === undefined) return null;
      let iri = parent.role_iri[0];
      const reducer = getReducer("ROLE");
      const sparqlQuery = selectRoleByIriQuery(iri, selectMap.getNode("role"));
      let response;
      try {
        response = await dataSources.Stardog.queryById({
          dbName,
          sparqlQuery,
          queryId: "Select Role",
          singularizeSchema
        });
      } catch (e) {
        console.log(e)
        throw e
      }
      if (response === undefined) return null;
      if (Array.isArray(response) && response.length > 0) {
        return (reducer(response[0]))
      }
      else {
        // Handle reporting Stardog Error
        if (typeof (response) === 'object' && 'body' in response) {
          throw new UserInputError(response.statusText, {
            error_details: (response.body.message ? response.body.message : response.body),
            error_code: (response.body.code ? response.body.code : 'N/A')
          });
        }
      }
      return null;  
    }
  }
}

export default responsibleRoleResolvers;
