import { assetSingularizeSchema as singularizeSchema } from '../asset-mappings.js';
import { getSparqlQuery, getReducer } from './sparql-query.js';


const softwareResolvers = {
  Query: {
    softwareAssetList: async ( _, args, context, info ) => {
      var sparqlQuery = getSparqlQuery('SOFTWARE');
      var reducer = getReducer('SOFTWARE');
      const response = await context.dataSources.Stardog.queryAll( 
        context.dbName, 
        sparqlQuery,
        singularizeSchema,
        args.first,       // limit
        args.offset,      // offset
        args.filter,      // filter
      );
      if (Array.isArray(response) && response.length > 0) {
        // build array of edges
        const edges = [];
        for (let asset of response) {
          let edge = {
            cursor: asset.iri,
            node: reducer( asset ),
          }
          if (edge.node.name === undefined) {
            console.log(edge)
          } else {
            edges.push( edge )
          }
        }
        return {
          pageInfo: {
            startCursor: response[0].iri,
            endCursor: response[response.length -1 ].iri,
            hasNextPage: false,
            hasPreviousPage: false,
            globalCount: response.length,
          },
          edges: edges,
        }
      } else {
        return [];
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