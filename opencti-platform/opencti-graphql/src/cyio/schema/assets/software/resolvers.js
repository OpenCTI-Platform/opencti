import { assetSingularizeSchema as singularizeSchema, objectTypeMapping } from '../asset-mappings.js';
import {
  getSelectSparqlQuery,
  getReducer,
  insertQuery, predicateMap,
} from './sparql-query.js';
import {compareValues, updateQuery} from '../../utils.js';
import {addToInventoryQuery, deleteQuery, removeFromInventoryQuery} from "../assetUtil";

const softwareResolvers = {
  Query: {
    softwareAssetList: async ( _, args, context, info ) => {
      const selectionList =  context.selectMap.getNode("node");
      const sparqlQuery = getSelectSparqlQuery('SOFTWARE', selectionList);
      const reducer = getReducer('SOFTWARE');
      const response = await context.dataSources.Stardog.queryAll( 
        context.dbName, 
        sparqlQuery,
        singularizeSchema,
        // args.first,       // limit
        // args.offset,      // offset
        args.filter,      // filter
      );
      if (Array.isArray(response) && response.length > 0) {
        // build array of edges
        const edges = [];
        let limit = (args.first === undefined ? response.length : args.first) ;
        let offset = (args.offset === undefined ? 0 : args.offset) ;
        const assetList = (args.orderedBy !== undefined) ? response.sort(compareValues(args.orderedBy, args.orderMode)) : response;

        for (const asset of assetList) {
          // skip down past the offset
          if ( offset ) {
            offset--
            continue
          }

          if ( limit ) {
            const edge = {
              cursor: asset.iri,
              node: reducer( asset ),
            }
            if (edge.node.name === undefined) {
              console.log(`[WARNING] Required field 'name' missing: ${edge}`)
            }
            edges.push( edge )
            limit-- ;
          }
        }
        return {
          pageInfo: {
            startCursor: assetList[0].iri,
            endCursor: assetList[assetList.length -1 ].iri,
            hasNextPage: (args.first > assetList.length ? true : false),
            hasPreviousPage: (args.offset > 0 ? true : false),
            globalCount: assetList.length,
          },
          edges: edges,
        }
      } else {
        return null;
      }
    },
    softwareAsset: async ( _, args, context, info ) => {
      var sparqlQuery = getSelectSparqlQuery('SOFTWARE', context.selectMap.getNode("softwareAsset"), args.id);
      var reducer = getReducer('SOFTWARE');
      const response = await context.dataSources.Stardog.queryById( context.dbName, sparqlQuery, singularizeSchema, )
      if (response === undefined ) return null;
      const first = response[0];
      if (first === undefined) return null;
      return( reducer( first ) );
    }
  },
  Mutation: {
    createSoftwareAsset: async ( _, {input}, context,  ) => {
      const dbName = context.dbName;
      const {iri, id, query} = insertQuery(input);
      await context.dataSources.Stardog.create(dbName, query);
      const connectQuery = addToInventoryQuery(iri);
      await context.dataSources.Stardog.create(dbName, connectQuery);
      return {...input, id};
    },
    deleteSoftwareAsset: async ( _, {id}, context,  ) => {
      const dbName = context.dbName;
      const relationshipQuery = removeFromInventoryQuery(id);
      await context.dataSources.Stardog.delete(dbName, relationshipQuery);
      const query = deleteQuery(id);
      await context.dataSources.Stardog.delete(dbName, query);
      return id;
    },
    editSoftwareAsset: async ( _, {id, input}, context,  ) => {
      const dbName = context.dbName;
      const query = updateQuery(
          `http://scap.nist.gov/ns/asset-identification#Software-${id}`,
          "http://scap.nist.gov/ns/asset-identification#Software",
          input,
          predicateMap
      );
      await context.dataSources.Stardog.edit(dbName, query);
      return {id};
    },
  },
  // Map enum GraphQL values to data model required values
  FamilyType: {
    windows: 'windows',
    linux: 'linux',
    macos: 'macos',
    other: 'other',
  },
  SoftwareKind: {
    __resolveType: ( item ) => {
      return objectTypeMapping[item.entity_type];
    }
  }
} ;
  
  
export default softwareResolvers ;
