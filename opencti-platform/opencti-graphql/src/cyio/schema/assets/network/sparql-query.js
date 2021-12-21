import {byIdClause, buildSelectVariables, optionalizePredicate, parameterizePredicate, generateId, OASIS_SCO_NS} from "../../utils.js";

const bindIRIClause = `\tBIND(<{iri}> AS ?iri)\n`;
const typeConstraint = `?iri a <http://scap.nist.gov/ns/asset-identification#Network> . \n`;
const inventoryConstraint = `
{
  SELECT DISTINCT ?iri
  WHERE {
    ?inventory a <http://csrc.nist.gov/ns/oscal/common#AssetInventory> ;
          <http://csrc.nist.gov/ns/oscal/common#assets> ?iri .
  }
}`;
// {
//     SELECT DISTINCT ?iri
//     WHERE {
//         GRAPH ?g {
//           ?inventory a <http://csrc.nist.gov/ns/oscal/common#AssetInventory> ;
//                 <http://csrc.nist.gov/ns/oscal/common#assets> ?iri .
//         }
//     }
// }`;

export function getSelectSparqlQuery(type, select, id, filter, ) {
  var sparqlQuery;
  let { selectionClause, predicates } = buildSelectVariables(predicateMap, select);
  selectionClause = `SELECT ${select.includes("id") ? "DISTINCT ?iri" : "?iri"} ${selectionClause}`;
  const selectPortion = `
  ${selectionClause}
  FROM <tag:stardog:api:context:named>
  WHERE {
      `;
  let iri;
  switch( type ) {
    case 'NETADDR-RANGE':
      iri = id == null ? "?iri" : `<http://scap.nist.gov/ns/asset-identification#IpAddressRange-${id}>`
      sparqlQuery = `
      ${selectionClause}
      FROM <tag:stardog:api:context:named>
      WHERE {
        ${iri} a <http://scap.nist.gov/ns/asset-identification#IpAddressRange> ;
        ${predicates}
      }
      `
      // ${selectionClause}
      // WHERE {
      //   GRAPH ${iri} {
      //       ${iri} a <http://scap.nist.gov/ns/asset-identification#IpAddressRange> ;
      //       ${predicates}
      //   }
      // }
      // `
      break;
    case 'NETWORK':
      iri = id == null ? "?iri" : `<http://scap.nist.gov/ns/asset-identification#Network-${id}>`
      let filterStr = '';
      let byId = '';
      if (id !== undefined) {
        byId = byIdClause(id);
      }
      sparqlQuery = selectPortion + typeConstraint + byId + predicates + inventoryConstraint + filterStr + '}';

      // sparqlQuery = `
      // ${selectionClause}
      // FROM <tag:stardog:api:context:named>
      // WHERE {
      //   ?iri a <http://scap.nist.gov/ns/asset-identification#Network> ;
      //   ${predicates} 
      //   ${inventoryConstraint} .
      //   ${filterStr}
      // }`
      // ${selectionClause}
      // WHERE {
      //   GRAPH ${iri} {
      //       ?iri a <http://scap.nist.gov/ns/asset-identification#Network> ;
      //       ${predicates} 
      //       ${inventoryConstraint} .
      //       ${filterStr}
      //   }
      // }
      // `
      break;
    case 'CONN-NET-IRI':
      sparqlQuery = selectPortion +
          bindIRIClause.replace('{iri}', id) + 
          typeConstraint +
          predicates + '}';
      break
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
      return networkAssetReducer ;
    case 'NETADDR-RANGE':
      return ipAddrRangeReducer;
    default:
      throw new Error(`Unsupported reducer type ' ${type}'`)
  }
}

export const predicateMap = {
  id: {
    predicate: "<http://darklight.ai/ns/common#id>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"`: null, this.predicate, "id")},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value))}
  },
  created: {
    predicate: "<http://darklight.ai/ns/common#created>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"^^xsd:dateTime`: null, this.predicate, "created")},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value))}
  },
  modified: {
    predicate: "<http://darklight.ai/ns/common#modified>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"^^xsd:dateTime`: null, this.predicate, "modified")},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value))}
  },
  labels: {
    predicate: "<http://darklight.ai/ns/common#labels>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"`: null, this.predicate, "labels")},
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
  asset_type: {
    predicate: "<http://scap.nist.gov/ns/asset-identification#asset_type>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"`: null, this.predicate, "asset_type")},
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
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"^^xsd:dateTime`: null, this.predicate, "release_date")},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value))}
  },
  implementation_point: {
    predicate: "<http://scap.nist.gov/ns/asset-identification#implementation_point>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"`: null, this.predicate, "implementation_point")},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value))}
  },
  operational_status: {
    predicate: "<http://scap.nist.gov/ns/asset-identification#operational_status>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"`: null, this.predicate, "operational_status")},
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
  is_publicly_accessible: {
    predicate: "<http://scap.nist.gov/ns/asset-identification#is_publicly_accessible>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"^^xsd:boolean`: null, this.predicate, "is_publicly_accessible")},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value))}
  },
  is_scanned: {
    predicate: "<http://scap.nist.gov/ns/asset-identification#is_scanned>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"^^xsd:boolean`: null, this.predicate, "is_scanned")},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value))}
  },
  last_scanned: {
    predicate: "<http://scap.nist.gov/ns/asset-identification#last_scanned>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"^^xsd:dateTime`: null, this.predicate, "last_scanned");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  }
}

export const insertQuery = (propValues) => {
  const id_material = {
    ...(propValues.network_name && { "network_name": propValues.network_name}),
    ...(propValues.network_id && {"network_id": propValues.network_id}),
  } ;
  const id = generateId( id_material, OASIS_SCO_NS );
  const timestamp = new Date().toISOString()
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
      ${iri} <http://darklight.ai/ns/common#object_type> "network" . 
      ${iri} <http://darklight.ai/ns/common#created> "${timestamp}"^^xsd:dateTime . 
      ${iri} <http://darklight.ai/ns/common#modified> "${timestamp}"^^xsd:dateTime . 
      ${insertPredicates}
    }
  }
  `
  return {iri, id, query}
}

export const deleteNetworkAssetQuery = (id) =>  {
  const iri = `<http://scap.nist.gov/ns/asset-identification#Network-${id}>`;
  return `
  DELETE {
    GRAPH ${iri} {
      ${iri} ?p ?o
    }
  } WHERE {
    GRAPH ${iri} {
      ${iri} a <http://scap.nist.gov/ns/asset-identification#Network> .
      ${iri} ?p ?o
    }  
  }
  `
}

export function networkAssetReducer( item ) {
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
    ...(item.is_publicly_accessible !== undefined && {is_publicly_accessible: item.is_publicly_accessible}),
    ...(item.is_scanned !== undefined && {is_scanned: item.is_scanned}),
    ...(item.last_scanned && {last_scanned: item.last_scanned}),
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
    console.log(`[NON-CONFORMANT] starting_ip_address is NOT an object`);
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
