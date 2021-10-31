import { assetSingularizeSchema as singularizeSchema } from '../asset-mappings.js';
import { getSparqlQuery, getReducer } from './sparql-query.js';
import { compareValues } from '../../utils.js';


const softwareResolvers = {
  Query: {
    softwareAssetList: async ( _, args, context, info ) => {
      var sparqlQuery = getSparqlQuery('SOFTWARE');
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
              console.log(`[DATA-ERROR]required field 'name' missing ${edge}`)
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
      var sparqlQuery = getSparqlQuery('SOFTWARE', args.id, );
      var reducer = getReducer('SOFTWARE');
      const response = await context.dataSources.Stardog.queryById( 
        context.dbName, 
        sparqlQuery, 
        singularizeSchema, 
      )
      // console.log( response[0] );
      return( reducer( response[0]) );
    }
  },
  Mutation: {
    createSoftwareAsset: ( parent, args, context, info ) => {
    },
    deleteSoftwareAsset: ( parent, args, context, info ) => {
    },
    editSoftwareAsset: ( parent, args, context, info ) => {
    },
  },
  // Map enum GraphQL values to data model required values
  FamilyType: {
    windows: 'windows',
    linux: 'linux',
    macos: 'macos',
    other: 'other',
  },
} ;
  
  
export default softwareResolvers ;