export function getSparqlQuery(type, id, filter, ) {
  var sparqlQuery;
  let re = /{iri}/g;  // using regex with 'g' switch to replace all instances of a marker
  switch( type ) {
    case 'SOFTWARE':
      let byId = '';
      let filterStr = '';
      if (id !== undefined) {
        byId = byIdClause.replace("{id}", id);
      }
      sparqlQuery = selectClause + 
          typeConstraint.replace('{softwareType}', 'Software') + 
          byId + 
          predicates + 
          inventoryConstraint + 
          filterStr + '}';
      break;
    case 'SOFTWARE-IRI':
      sparqlQuery = selectClause + 
          bindIRIClause.replace('{iri}', id) + 
          typeConstraint.replace('{softwareType}', 'Software') +
          predicates + '}';
        // console.log(`[INFO] Query = ${sparqlQuery}`)
      break;
    case 'OS-IRI':
      sparqlQuery = selectClause + 
          bindIRIClause.replace('{iri}', id) + 
          typeConstraint.replace('{softwareType}', 'OperatingSystem') +
          predicates + '}';
      // console.log(`[INFO] Query = ${sparqlQuery}`)
      break
    default:
      throw new Error(`Unsupported query type ' ${type}'`)
  }

  return sparqlQuery ;
}

export function getReducer( type ) {
  var reducer;
  switch( type ) {
    case 'SOFTWARE':
    case 'SOFTWARE-IRI':
    case 'OS-IRI': 
      reducer = softwareAssetReducer;
      break;
    default:
      throw new Error(`Unsupported reducer type ' ${type}'`)
  }

  return reducer
}

const selectClause = `
SELECT DISTINCT ?iri ?rdf_type ?id ?object_type 
  ?asset_id ?name ?description ?locations ?responsible_party 
  ?asset_type ?asset_tag ?serial_number ?vendor_name ?version ?release_date
  ?function ?cpe_identifier ?software_identifier ?patch ?installation_id ?license_key
FROM <tag:stardog:api:context:named>
WHERE {
`;

const bindIRIClause = `\tBIND(<{iri}> AS ?iri)\n`;
const typeConstraint = `?iri a <http://scap.nist.gov/ns/asset-identification#{softwareType}> .`;
const byIdClause = `?iri <http://darklight.ai/ns/common#id> "{id}" .`;

const predicates = `
    ?iri <http://darklight.ai/ns/common#id> ?id .
    ?iri <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> ?rdf_type .
    OPTIONAL { ?iri <http://scap.nist.gov/ns/asset-identification#asset_id> ?asset_id } .
    OPTIONAL { ?iri <http://scap.nist.gov/ns/asset-identification#name> ?name } .
    OPTIONAL { ?iri <http://scap.nist.gov/ns/asset-identification#description> ?description } .
    OPTIONAL { ?iri <http://scap.nist.gov/ns/asset-identification#locations> ?locations } .
    # OPTIONAL { ?iri <http://scap.nist.gov/ns/asset-identification#responsible_parties> ?responsible_party } .
    # ItAsset
    OPTIONAL { ?iri <http://scap.nist.gov/ns/asset-identification#asset_type> ?asset_type } .
    OPTIONAL { ?iri <http://scap.nist.gov/ns/asset-identification#asset_tag> ?asset_tag } .
    OPTIONAL { ?iri <http://scap.nist.gov/ns/asset-identification#serial_number> ?serial_number } .
    OPTIONAL { ?iri <http://scap.nist.gov/ns/asset-identification#vendor_name> ?vendor_name }.
    OPTIONAL { ?iri <http://scap.nist.gov/ns/asset-identification#version> ?version } .
    OPTIONAL { ?iri <http://scap.nist.gov/ns/asset-identification#release_date> ?release_date } .
    # Software - OperatingSystem - ApplicationSoftware
    OPTIONAL { ?iri <http://scap.nist.gov/ns/asset-identification#function> ?function } .
    OPTIONAL { ?iri <http://scap.nist.gov/ns/asset-identification#cpe_identifier> ?cpe_identifier } .
    OPTIONAL { ?iri <http://scap.nist.gov/ns/asset-identification#software_identifier> ?software_identifier } .
    OPTIONAL { ?iri <http://scap.nist.gov/ns/asset-identification#patch_level> ?patch } .
    OPTIONAL { ?iri <http://scap.nist.gov/ns/asset-identification#installation_id> ?installation_id }
    OPTIONAL { ?iri <http://scap.nist.gov/ns/asset-identification#license_key> ?license_key } .
    `;
    
  const inventoryConstraint = `
  {
      SELECT DISTINCT ?iri
      WHERE {
          ?inventory a <http://csrc.nist.gov/ns/oscal/common#AssetInventory> ;
                <http://csrc.nist.gov/ns/oscal/common#assets> ?iri .
      }
  }`;

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
  