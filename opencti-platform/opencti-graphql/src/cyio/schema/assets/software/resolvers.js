import { responsePathAsArray } from 'graphql';
import { assetSingularizeSchema as singularizeSchema } from '../asset-mappings.js';
import { getSparqlQuery } from './sparql-query.js';


const softwareResolvers = {
  Query: {
    softwareAssetList: async ( _, args, context, info ) => {
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
    ...(asset.created && {created: asset.created}),
    ...(asset.modified && {modified: asset.modified}),
    ...(asset.labels && {labels: asset.labels}),
    ...(asset.name && { name: asset.name} ),
    ...(asset.description && { description: asset.description}),
    ...(asset.asset_id && { asset_id: asset.asset_id}),
    ...(asset.asset_type && {asset_type: asset.asset_type}),
    ...(asset.asset_tag && {asset_tag: asset.asset_tag}) ,
    ...(asset.serial_number && {serial_number: asset.serial_number}),
    ...(asset.vendor_name && {vendor_name: asset.vendor_name}),
    ...(asset.version && {version: asset.version}),
    ...(asset.release_date && {release_date: asset.release_date}),
    ...(asset.function && {function: asset.function}),
    ...(asset.cpe_identifier && {cpe_identifier: asset.cpe_identifier}),
    ...(asset.software_identifier && {software_identifier: asset.software_identifier}),
    ...(asset.patch_level && {patch_level: asset.patch_level}),
    ...(asset.installation_id && {installation_id: asset.installation_id}),
    ...(asset.license_key && {license_key: asset.license_key}),
    // Hints
    ...(asset.iri && {parent_iri: asset.iri}),
    ...(asset.locations && {locations_iri: asset.locations}),
    ...(asset.external_references && {ext_ref_iri: asset.external_references}),
    ...(asset.notes && {notes_iri: asset.notes}),
  }
}
  
export default softwareResolvers ;