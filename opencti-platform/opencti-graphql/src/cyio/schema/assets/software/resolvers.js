import { assetSingularizeSchema as singularizeSchema, objectTypeMapping } from '../asset-mappings.js';
import {
  getSelectSparqlQuery,
  getReducer,
  insertQuery,
  addToInventoryQuery,
  deleteQuery,
  removeFromInventoryQuery,
  QueryMode, updateSoftwareQuery
} from './sparql-query.js';
import {compareValues, queryPropertyMap} from '../../utils.js';


const softwareResolvers = {
  Query: {
    softwareAssetList: async ( _, args, context, info ) => {
      const propMap = queryPropertyMap(info);
      const rep = JSON.stringify(propMap);
      var sparqlQuery = getSelectSparqlQuery('SOFTWARE');
      var reducer = getReducer('SOFTWARE');
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
        let assetList ;
        if (args.orderedBy !== undefined ) {
          assetList = response.sort(compareValues(args.orderedBy, args.orderMode ));
        } else {
          assetList = response;
        }

        for (let asset of assetList) {
          // skip down past the offset
          if ( offset ) {
            offset--
            continue
          }

          if ( limit ) {
            let edge = {
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
        return ;
      }
    },
    softwareAsset: async ( _, args, context, info ) => {
      var sparqlQuery = getSelectSparqlQuery('SOFTWARE', args.id, );
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
      const updateQuery = updateSoftwareQuery(id, input)
      await context.dataSources.Stardog.edit(dbName, updateQuery);
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