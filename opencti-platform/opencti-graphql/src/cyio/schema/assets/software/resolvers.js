import { responsePathAsArray } from 'graphql';
import { assetSingularizeSchema as singularizeSchema } from '../asset-mappings.js';
import { getSparqlQuery } from './sparql-query.js';


const softwareResolvers = {
  Query: {
    softwareAssetList: async ( _, args, context, info ) => {
      console.log('*** Resolver: In softwareAssetList')
      var sparqlQuery = getSparqlQuery('BY-ALL', args.id);
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
            node: softwareAssetReducer( asset ),
          }
          edges.push( edge )
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
      console.log('*** Resolver: In softwareAsset')
      const dbName = context.dbName;
      var sparqlQuery = getSparqlQuery('BY-ID', args.id);
      const response = await context.dataSources.Stardog.queryById( dbName, sparqlQuery, singularizeSchema, )
      console.log( response[0] );
      return( softwareAssetReducer( response[0]) );
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
  
function softwareAssetReducer( asset ) {
  return {
    id: asset.id,
    name: asset.name || null,
    description: asset.description || null,
    asset_id: asset.asset_id || null,
    asset_type: asset.asset_type || null,
    asset_tag: asset.tag || null,
    serial_number: asset.serial_number || null,
    vendor_name: asset.vendor_name || null,
    version: asset.version || null,
    release_date: asset.release_date || null,
    function: asset.function || null,
    cpe_identifier: asset.cpe_identifier || null,
    software_identifier: asset.software_identifier || null,
    patch_level: asset.patch_level || null,
    installation_id: asset.installation_id || null,
    license_key: asset.license_key || null,
    // Hints
    parent_iri: asset.iri,
    locations_iri: asset.locations || null,
    ext_ref_iri: asset.external_references || null,
    notes_iri: asset.notes || null,
  }
}
  
export default softwareResolvers ;