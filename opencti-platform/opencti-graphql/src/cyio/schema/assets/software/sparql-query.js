import {UpdateOps, byIdClause, optionalizePredicate, parameterizePredicate, buildSelectVariables, generateId, OASIS_SCO_NS} from "../../utils.js";

export const predicateMap = {
  id: {
    predicate: "<http://darklight.ai/ns/common#id>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"` : null,  this.predicate, "id");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
  created: {
    predicate: "<http://darklight.ai/ns/common#created>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"^^xsd:dateTime`: null,  this.predicate, "created");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
  modified: {
    predicate: "<http://darklight.ai/ns/common#modified>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"^^xsd:dateTime`: null,  this.predicate, "modified");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
  labels: {
    predicate: "<http://darklight.ai/ns/common#labels>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"`: null,  this.predicate, "labels");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
  asset_id: {
    predicate: "<http://scap.nist.gov/ns/asset-identification#asset_id>",
    binding: function (iri, value) { return  parameterizePredicate(iri, value ? `"${value}"` : null,  this.predicate, "asset_id");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
  name: {
    predicate: "<http://scap.nist.gov/ns/asset-identification#name>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"` : null,  this.predicate, "name");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
  description: {
    predicate: "<http://scap.nist.gov/ns/asset-identification#description>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"` : null,  this.predicate, "description");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
  location: {
    predicate: "<http://scap.nist.gov/ns/asset-identification#locations>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"` : null,  this.predicate, "location");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
  asset_type: {
    predicate: "<http://scap.nist.gov/ns/asset-identification#asset_type>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"` : null,  this.predicate, "asset_type");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
  asset_tag: {
    predicate: "<http://scap.nist.gov/ns/asset-identification#asset_tag>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"` : null,  this.predicate, "asset_tag");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
  serial_number: {
    predicate: "<http://scap.nist.gov/ns/asset-identification#serial_number>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"` : null,  this.predicate, "serial_number");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
  vendor_name: {
    predicate: "<http://scap.nist.gov/ns/asset-identification#vendor_name>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"` : null,  this.predicate, "vendor_name");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
  version: {
    predicate: "<http://scap.nist.gov/ns/asset-identification#version>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"` : null,  this.predicate, "version");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
  release_date: {
    predicate: "<http://scap.nist.gov/ns/asset-identification#release_date>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"^^xsd:dateTime`: null,  this.predicate, "release_date");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
  implementation_point: {
    predicate: "<http://scap.nist.gov/ns/asset-identification#implementation_point>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"` : null,  this.predicate, "implementation_point");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
  operational_status: {
    predicate: "<http://scap.nist.gov/ns/asset-identification#operational_status>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"` : null,  this.predicate, "operational_status");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
  function: {
    predicate: "<http://scap.nist.gov/ns/asset-identification#function>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"` : null,  this.predicate, "function");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
  cpe_identifier: {
    predicate: "<http://scap.nist.gov/ns/asset-identification#cpe_identifier>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"` : null,  this.predicate, "cpe_identifier");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
  software_identifier: {
    predicate: "<http://scap.nist.gov/ns/asset-identification#software_identifier>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"` : null,  this.predicate, "software_identifier")},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));}
  },
  patch: {
    predicate: "<http://scap.nist.gov/ns/asset-identification#patch_level>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"` : null,  this.predicate, "patch");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));}
  },
  installation_id: {
    predicate: "<http://scap.nist.gov/ns/asset-identification#installation_id>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"` : null,  this.predicate, "installation_id");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));}
  },
  license_key: {
    predicate: "<http://scap.nist.gov/ns/asset-identification#license_key>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"` : null,  this.predicate, "license_key");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));}
  },
  is_publicly_accessible: {
    predicate: "<http://scap.nist.gov/ns/asset-identification#is_publicly_accessible>",
    binding: function (iri, value) { return parameterizePredicate(iri, value !== undefined ? `"${value}"^^xsd:boolean`: null, this.predicate, "is_publicly_accessible")},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value))}
  },
  is_scanned: {
    predicate: "<http://scap.nist.gov/ns/asset-identification#is_scanned>",
    binding: function (iri, value) { return parameterizePredicate(iri, value !== undefined ? `"${value}"^^xsd:boolean`: null, this.predicate, "is_scanned")},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value))}
  },
  last_scanned: {
    predicate: "<http://scap.nist.gov/ns/asset-identification#last_scanned>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"^^xsd:dateTime`: null, this.predicate, "last_scanned");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
}

const predicateBody = `
    ?iri <http://darklight.ai/ns/common#id> ?id .
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

const bindIRIClause = `\tBIND(<{iri}> AS ?iri)\n`;
const typeConstraint = `?iri a <http://scap.nist.gov/ns/asset-identification#{softwareType}> . \n`;

const inventoryConstraint = `
{
    SELECT DISTINCT ?iri
    WHERE {
        ?inventory a <http://csrc.nist.gov/ns/oscal/common#AssetInventory> ;
              <http://csrc.nist.gov/ns/oscal/common#assets> ?iri .
    }
}`;

export const insertQuery = (propValues) => {
  const id_material = {
    ...(propValues.name && { "name": propValues.name}),
    ...(propValues.cpe_identifier && {"cpe": propValues.cpe_identifier}),
    ...(propValues.software_identifier && {"swid": propValues.software_identifier}),
    ...(propValues.vendor_name && {"vendor": propValues.vendor_name}),
    ...(propValues.version && {"version": propValues.version})
  } ;
  const id = generateId( id_material, OASIS_SCO_NS );
  const timestamp = new Date().toISOString()
  const iri = `<http://scap.nist.gov/ns/asset-identification#Software-${id}>`;
  const insertPredicates = Object.entries(propValues)
    .filter((propPair) => predicateMap.hasOwnProperty(propPair[0]))
    .map((propPair) => predicateMap[propPair[0]].binding(iri, propPair[1]))
    .join('.\n      ');
  const query = `
  INSERT DATA {
    GRAPH ${iri} {
      ${iri} a <http://scap.nist.gov/ns/asset-identification#Software> .
      ${iri} a <http://scap.nist.gov/ns/asset-identification#ItAsset> .
      ${iri} a <http://scap.nist.gov/ns/asset-identification#Asset> .
      ${iri} a <http://darklight.ai/ns/common#Object> . 
      ${iri} <http://darklight.ai/ns/common#id> "${id}".
      ${iri} <http://darklight.ai/ns/common#object_type> "software" . 
      ${iri} <http://darklight.ai/ns/common#created> "${timestamp}"^^xsd:dateTime . 
      ${iri} <http://darklight.ai/ns/common#modified> "${timestamp}"^^xsd:dateTime . 
      ${insertPredicates}
    }
  }
  `;
  return {iri, id, query}
};

export const QueryMode = {
  BY_ALL: 'BY_ALL',
  BY_ID: 'BY_ID'
}

export function getSelectSparqlQuery(type, select, id, filter) {
  let sparqlQuery;
  let { selectionClause, predicates } = buildSelectVariables(predicateMap, select)
  selectionClause = `SELECT ${select.includes("id") ? "DISTINCT ?iri" : "?iri"} ${selectionClause}`;
  const selectPortion = `
  ${selectionClause}
  FROM <tag:stardog:api:context:named>
  WHERE {
    `;
    switch( type ) {
    case 'SOFTWARE':
      let byId = '';
      if (id !== undefined) {
        byId = byIdClause(id);
      }

      let filterStr = ''
      sparqlQuery = selectPortion +
          typeConstraint.replace('{softwareType}', 'Software') + 
          byId + 
          predicates +
          inventoryConstraint + 
          filterStr + '}';
      break;
    case 'SOFTWARE-IRI':
      sparqlQuery = selectPortion +
          bindIRIClause.replace('{iri}', id) + 
          typeConstraint.replace('{softwareType}', 'Software') +
          predicates + '}';
      break;
    case 'OS-IRI':
      sparqlQuery = selectPortion +
          bindIRIClause.replace('{iri}', id) + 
          typeConstraint.replace('{softwareType}', 'OperatingSystem') +
          predicates + '}';
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

  
function softwareAssetReducer( item ) {
  // if no object type was returned, compute the type from the IRI
  if ( item.object_type === undefined && item.asset_type !== undefined ) {
    item.object_type = item.asset_type
  } else {
    item.object_type = 'software';
  }

  return {
    id: item.id,
    ...(item.object_type && {entity_type: item.object_type}),
    ...(item.created && {created: item.created}),
    ...(item.modified && {modified: item.modified}),
    ...(item.name && { name: item.name} ),
    ...(item.description && { description: item.description}),
    ...(item.asset_id && { asset_id: item.asset_id}),
    // ItAsset      
    ...(item.asset_type && {asset_type: item.asset_type}),
    ...(item.asset_tag && {asset_tag: item.asset_tag}) ,
    ...(item.serial_number && {serial_number: item.serial_number}),
    ...(item.vendor_name && {vendor_name: item.vendor_name}),
    ...(item.version && {version: item.version}),
    ...(item.release_date && {release_date: item.release_date}),
    // Software - OperatingSystem - ApplicationSoftware
    ...(item.function && {function: item.function}),
    ...(item.cpe_identifier && {cpe_identifier: item.cpe_identifier}),
    ...(item.software_identifier && {software_identifier: item.software_identifier}),
    ...(item.patch_level && {patch_level: item.patch_level}),
    ...(item.installation_id && {installation_id: item.installation_id}),
    ...(item.license_key && {license_key: item.license_key}),
    ...(item.is_publicly_accessible !== undefined && {is_publicly_accessible: item.is_publicly_accessible}),
    ...(item.is_scanned !== undefined && {is_scanned: item.is_scanned}),
    ...(item.last_scanned && {last_scanned: item.last_scanned}),
    // Hints
    ...(item.iri && {parent_iri: item.iri}),
    ...(item.locations && {locations_iri: item.locations}),
    ...(item.external_references && {ext_ref_iri: item.external_references}),
	  ...(item.labels && {labels_iri: item.labels}),
    ...(item.notes && {notes_iri: item.notes}),
  }
}
