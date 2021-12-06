import {buildSelectVariables, optionalizePredicate, parameterizePredicate} from "../../utils";

export function getSelectSparqlQuery(type, select, id, filter, ) {
  var sparqlQuery;
  if(select.includes("id")){
    select = select.filter((s) => s !== "id");
    select.unshift("id");
  }
  let { selectionClause, predicates } = buildSelectVariables(predicateMap, select);
  selectionClause = `SELECT ${select.includes("id") ? "DISTINCT" : ""} ${selectionClause}`;
  let iri;
  switch( type ) {
    case 'NETADDR-RANGE':
      iri = id == null ? "?iri" : `<http://scap.nist.gov/ns/asset-identification#IpAddressRange-${id}>`
      sparqlQuery = `
      ${selectionClause}
      WHERE {
        GRAPH ${iri} {
          ${iri} a <http://scap.nist.gov/ns/asset-identification#IpAddressRange> ;
          ${predicates}
        }
      }
      `
      break;
    case 'NETWORK':
      iri = id == null ? "?iri" : `<http://scap.nist.gov/ns/asset-identification#Network-${id}>`
      let filterStr = '';
      sparqlQuery = `
      ${selectionClause}
      WHERE {
        GRAPH ${iri} {
            ?iri a <http://scap.nist.gov/ns/asset-identification#Network> ;
            ${predicates} .
            ${filterStr}
        }
      }
      `
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

const predicateMap = {
  id: {
    predicate: "<http://darklight.ai/ns/common#id>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"`: null, this.predicate, "id")},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value))}
  },
  asset_id: {
    predicate: "<http://scap.nist.gov/ns/asset-identification#asset_id>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"`: null, this.predicate, "asset_id")},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value))}
  },
  name: {
    predicate: "<http://scap.nist.gov/ns/asset-identification#name>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"`: null, this.predicate, "name")},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value))}
  },
  description: {
    predicate: "<http://scap.nist.gov/ns/asset-identification#description>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"`: null, this.predicate, "description")},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value))}
  },
  locations: {
    predicate: "<http://scap.nist.gov/ns/asset-identification#locations>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"`: null, this.predicate, "locations")},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value))}
  },
  asset_tag: {
    predicate: "<http://scap.nist.gov/ns/asset-identification#asset_tag>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"`: null, this.predicate, "asset_tag")},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value))}
  },
  serial_number: {
    predicate: "<http://scap.nist.gov/ns/asset-identification#serial_number>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"`: null, this.predicate, "serial_number")},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value))}
  },
  vendor_name: {
    predicate: "<http://scap.nist.gov/ns/asset-identification#vendor_name>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"`: null, this.predicate, "vendor_name")},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value))}
  },
  version: {
    predicate: "<http://scap.nist.gov/ns/asset-identification#version>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"`: null, this.predicate, "version")},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value))}
  },
  release_date: {
    predicate: "<http://scap.nist.gov/ns/asset-identification#release_date>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"^^xsd:datetime`: null, this.predicate, "release_date")},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value))}
  },
  network_id: {
    predicate: "<http://scap.nist.gov/ns/asset-identification#network_id>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"`: null, this.predicate, "network_id")},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value))}
  },
  network_name: {
    predicate: "<http://scap.nist.gov/ns/asset-identification#network_name>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"`: null, this.predicate, "network_name")},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value))}
  },
  network_address_range: {
    predicate: "<http://scap.nist.gov/ns/asset-identification#network_address_range>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"`: null, this.predicate, "network_address_range")},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value))}
  },
}

export const insertQuery = (propValues) => {
  const id = uuid4();
  const iri = `<http://scap.nist.gov/ns/asset-identification#Network-${id}>`;
  const insertPredicates = Object.entries(propValues)
      .filter((propPair) => predicateMap.hasOwnProperty(propPair[0]))
      .map((propPair) => predicateMap[propPair[0]].binding(iri, propPair[1]))
      .join('.\n      ')
  const query = `
  INSERT DATA {
    GRAPH ${iri} {
      ${iri} a <http://scap.nist.gov/ns/asset-identification#Network> .
      ${iri} a <http://scap.nist.gov/ns/asset-identification#ItAsset> .
      ${iri} a <http://scap.nist.gov/ns/asset-identification#Asset> .
      ${iri} a <http://darklight.ai/ns/common#Object> .
      ${iri} <http://darklight.ai/ns/common#id> "${id}".
      ${insertPredicates}
    }
  }
  `
  return {iri, id, query}
}

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
