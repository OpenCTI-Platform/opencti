export function getSelectSparqlQuery(type, id, filter, ) {
  var sparqlQuery;
  let re = /{iri}/g;  // using regex with 'g' switch to replace all instances of a marker
  switch( type ) {
    case 'NETADDR-RANGE':
      sparqlQuery = ipAddrRange.replace(re, id);
      break;
    case 'NETWORK':
      let byId = '';
      let filterStr = '';
      if (id !== undefined) {
        byId = byIdClause.replace("{id}", id);
      }
      sparqlQuery = selectClause + 
          typeConstraint + 
          byId + 
          predicates + 
          inventoryConstraint + 
          filterStr + '}';
      break;
    default:
      throw new Error(`Unsupported query type ' ${type}'`)
  }
  // console.log(`[INFO] Query = ${sparqlQuery}`)
  return sparqlQuery ;
}

export function getReducer( type ) {
  var reducer ;
  switch( type ) {
    case 'NETWORK':
      reducer = networkAssetReducer ;
      break ;
    case 'NETADDR-RANGE':
      reducer = ipAddrRangeReducer;
      break
    default:
      throw new Error(`Unsupported reducer type ' ${type}'`)
  }
  return reducer ;
}


const selectClause = `
SELECT DISTINCT ?iri ?id
  ?asset_id ?name ?description ?locations ?responsible_party 
  ?asset_type ?asset_tag ?serial_number ?vendor_name ?version ?release_date
  ?network_id ?network_name ?network_address_range 
FROM <tag:stardog:api:context:named>
WHERE {
`;

const bindIRIClause = `\tBIND(<{iri}> AS ?iri)\n`;
const typeConstraint = `?iri a <http://scap.nist.gov/ns/asset-identification#Network> .`;
const byIdClause = `?iri <http://darklight.ai/ns/common#id> "{id}" .`;

const predicates = `
?iri <http://darklight.ai/ns/common#id> ?id .
# OPTIONAL { ?iri <http://darklight.ai/ns/common#id> ?id } .
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
# Network
OPTIONAL { ?iri <http://scap.nist.gov/ns/asset-identification#network_id> ?network_id } .
OPTIONAL { ?iri <http://scap.nist.gov/ns/asset-identification#network_name> ?network_name } .
OPTIONAL { ?iri <http://scap.nist.gov/ns/asset-identification#network_address_range> ?network_address_range } .
`;

const inventoryConstraint = `
    {
        SELECT DISTINCT ?iri
        WHERE {
            ?inventory a <http://csrc.nist.gov/ns/oscal/common#AssetInventory> ;
                 <http://csrc.nist.gov/ns/oscal/common#assets> ?iri .
        }
    }
` ;

const ipAddrRange = `SELECT DISTINCT ?id ?object_type ?starting_ip_address ?ending_ip_address 
FROM <tag:stardog:api:context:named>
WHERE {
    <{iri}> a <http://scap.nist.gov/ns/asset-identification#IpAddressRange> ;
        <http://darklight.ai/ns/common#id> ?id  ;
        <http://scap.nist.gov/ns/asset-identification#starting_ip_address> ?starting_ip_address ;
        <http://scap.nist.gov/ns/asset-identification#ending_ip_address> ?ending_ip_address .
    OPTIONAL { <{iri}> <http://darklight.ai/ns/common#object_type> ?object_type } .
}`;

function networkAssetReducer( item ) {
  // if no object type was returned, compute the type from the IRI
  if ( item.object_type === undefined && item.asset_type !== undefined ) {
    item.object_type = item.asset_type
  } else {
    item.object_type = 'network';
  }
  
  return {
    id: item.id,
    ...(item.object_type && {entity_type: item.object_type}),
    ...(item.created && {created: item.created}),
    ...(item.modified && {modified: item.modified}),
    ...(item.labels && {labels: item.labels}),
    ...(item.name && {name: item.name}),
    ...(item.description && { description: item.description}),
    ...(item.asset_id && { asset_id: item.asset_id}),
    // ItAsset
    ...(item.asset_type && {asset_type: item.asset_type}),
    ...(item.asset_tag && {asset_tag: item.asset_tag}) ,
    ...(item.serial_number && {serial_number: item.serial_number}),
    ...(item.vendor_name && {vendor_name: item.vendor_name}),
    ...(item.version && {version: item.version}),
    ...(item.release_date && {release_date: item.release_date}),
    // Network
    ...(item.network_id && {network_id: item.network_id}),
    ...(item.network_name && {network_name: item.network_name}),
    // Hints
    ...(item.iri && {parent_iri: item.iri}),
    ...(item.locations && {locations_iri: item.locations}),
    ...(item.external_references && {ext_ref_iri: item.external_references}),
    ...(item.notes && {notes_iri: item.notes}),
    ...(item.network_address_range && {netaddr_range_iri: item.network_address_range}),
  }
}

function ipAddrRangeReducer ( item ) {
  if ( typeof item.starting_ip_address == 'string' ) {
    console.log(`[ERROR] Value not compliant: starting_ip_address is a string not object`);
  }
  // if no object type was returned, compute the type from the IRI
  if ( item.object_type === undefined && item.asset_type !== undefined ) {
    item.object_type = item.asset_type
  } else {
    item.object_type = 'ip-addr-range';
  }

  return {
    id: item.id,
    ...(item.object_type && {entity_type: item.object_type}),
    ...(item.iri &&{parent_iri: item.iri}),
    // Hints
    ...(item.starting_ip_address && {start_addr_iri: item.starting_ip_address}),
    ...(item.ending_ip_address && {ending_addr_iri: item.ending_ip_address}),
  }
}
