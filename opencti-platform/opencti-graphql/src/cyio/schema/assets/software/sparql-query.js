import {v4 as uuid4} from 'uuid';

const selectQueryForm = `
SELECT ?iri ?id ?object_type 
  ?asset_id ?name ?description ?locations ?responsible_party 
  ?asset_type ?asset_tag ?serial_number ?vendor_name ?version ?release_date
  ?function ?cpe_identifier ?software_identifier ?patch ?installation_id ?license_key
FROM <tag:stardog:api:context:local>
WHERE {
    ?iri a <http://scap.nist.gov/ns/asset-identification#Software> .
`;

const byIdClause = (id) => `?iri <http://darklight.ai/ns/common#id> "${id}" .`;
const predicateList = {
   'id': (iri ,id) => `${iri} <http://darklight.ai/ns/common#id> "${id}" .`,
   'asset_id' : (iri, asset_id) => `${iri} <http://scap.nist.gov/ns/asset-identification#asset_id> "${asset_id}" .`,
   'name' : (iri, name) => `${iri} <http://scap.nist.gov/ns/asset-identification#name> "${name}" .`,
   'description' : (iri, description) => `${iri} <http://scap.nist.gov/ns/asset-identification#description> "${description}" .`,
   'locations' : (iri, locations) => `${iri} <http://scap.nist.gov/ns/asset-identification#locations> "${locations}" .`,
   // 'responsible_party' : (responsibly_part) => '#?iri <http://scap.nist.gov/ns/asset-identification#responsible_parties> ' + (responsibly_part || '?responsible_party') + ' .',
   'asset_type' : (iri, asset_type) => `${iri} <http://scap.nist.gov/ns/asset-identification#asset_type> "${asset_type}" .`,
   'asset_tag' : (iri, asset_tag) => `${iri} <http://scap.nist.gov/ns/asset-identification#asset_tag> "${asset_tag}" .`,
   'serial_number': (iri, serial_number) => `${iri} <http://scap.nist.gov/ns/asset-identification#serial_number> "${serial_number}" .`,
   'vendor_name': (iri, vendor_name) => `${iri} <http://scap.nist.gov/ns/asset-identification#vendor_name> "${vendor_name}" .`,
   'version': (iri, version) => `${iri} <http://scap.nist.gov/ns/asset-identification#version> "${version}" .`,
   'release_date': (iri, release_date) => `${iri} <http://scap.nist.gov/ns/asset-identification#release_date> "${release_date}"^^xsd:datetime .` ,
   'function': (iri, $function) => `${iri} <http://scap.nist.gov/ns/asset-identification#function> "${$function}" .`,
   'cpe_identifier': (iri, cpe_identifier) => `${iri} <http://scap.nist.gov/ns/asset-identification#cpe_identifier> "${cpe_identifier}" .`,
   'software_identifier': (iri, software_identifier) => `${iri} <http://scap.nist.gov/ns/asset-identification#software_identifier> "${software_identifier}" .`,
   'patch': (iri, patch) => `${iri} <http://scap.nist.gov/ns/asset-identification#patch_level> "${patch}" .`,
   'installation_id': (iri, installation_id) => `${iri} <http://scap.nist.gov/ns/asset-identification#installation_id> "${installation_id}" . `,
   'license_key': (iri, license_key) => `${iri} <http://scap.nist.gov/ns/asset-identification#license_key> "${license_key}" .`
}

const predicates = `
    ?iri <http://darklight.ai/ns/common#id> ?id .
    # ItAsset
    OPTIONAL { ?iri <http://scap.nist.gov/ns/asset-identification#asset_id> ?asset_id }.
    OPTIONAL { ?iri <http://scap.nist.gov/ns/asset-identification#name> ?name }.
    OPTIONAL { ?iri <http://scap.nist.gov/ns/asset-identification#description> ?description }.
    OPTIONAL { ?iri <http://scap.nist.gov/ns/asset-identification#locations> ?locations }.
    # OPTIONAL { ?iri <http://scap.nist.gov/ns/asset-identification#responsible_parties> ?responsible_parties }.
    OPTIONAL { ?iri <http://scap.nist.gov/ns/asset-identification#asset_type> ?asset_type }.
    OPTIONAL { ?iri <http://scap.nist.gov/ns/asset-identification#asset_tag> ?asset_tag }.
    OPTIONAL { ?iri <http://scap.nist.gov/ns/asset-identification#vendor_name> ?vendor_name }.
    OPTIONAL { ?iri <http://scap.nist.gov/ns/asset-identification#serial_number> ?serial_number }.
    OPTIONAL { ?iri <http://scap.nist.gov/ns/asset-identification#version> ?version } .
    OPTIONAL { ?iri <http://scap.nist.gov/ns/asset-identification#release_date> ?release_date } .
    # Software - OperatingSystem - ApplicationSoftware
    OPTIONAL { ?iri <http://scap.nist.gov/ns/asset-identification#function> ?function } .
    OPTIONAL { ?iri <http://scap.nist.gov/ns/asset-identification#cpe_identifier> ?cpe_identifier } .
    OPTIONAL { ?iri <http://scap.nist.gov/ns/asset-identification#software_identifier> ?software_identifier } .
    OPTIONAL { ?iri <http://scap.nist.gov/ns/asset-identification#patch_level> ?patch } .
    OPTIONAL { ?iri <http://scap.nist.gov/ns/asset-identification#installation_id> ?installation_id } .
    OPTIONAL { ?iri <http://scap.nist.gov/ns/asset-identification#license_key> ?license_key } .
    `;
    
  const inventoryConstraint = `
  {
      SELECT DISTINCT ?iri
      WHERE {
          ?inventory a <http://csrc.nist.gov/ns/oscal/common#AssetInventory> ;
                <http://csrc.nist.gov/ns/oscal/common#assets> ?iri .
      }
  }
`;

export const insertQuery = (propValues) => {
  const id = uuid4();
  const iri = `<http://scap.nist.gov/ns/asset-identification#Software-${id}>`;
  const predicates = Object.entries(propValues)
    .filter((propPair) => predicateList.hasOwnProperty(propPair[0]))
    .map((propPair) => `${predicateList[propPair[0]].call(null, iri, propPair[1])}`)
    .join('\n    ');
  const query = `
  INSERT DATA {
    GRAPH ${iri} {
      ${iri} a <http://scap.nist.gov/ns/asset-identification#Software> .
      ${iri} <http://darklight.ai/ns/common#id> "${id}".
      ${predicates}
    }
  }
  `;
  return {iri, id, query}
};

export const deleteQuery = (id) => {
  return `
  DELETE {
    GRAPH ?g{
      ?iri ?p ?o
    }
  } WHERE {
    GRAPH ?g{
      ?iri a <http://scap.nist.gov/ns/asset-identification#Software> .
      ?iri <http://darklight.ai/ns/common#id> "${id}". 
      ?iri ?p ?o
    }
  }
  `
}

export const removeFromInventoryQuery = (id) => {
  return `
  DELETE {
    GRAPH ?g {
      ?inv <http://csrc.nist.gov/ns/oscal/common#assets> <http://scap.nist.gov/ns/asset-identification#Software-${id}> .
    }
  } WHERE {
    GRAPH ?g {
      ?inv a <http://csrc.nist.gov/ns/oscal/common#AssetInventory> .
    }
  }
  `
}

export const QueryMode = {
  BY_ALL: 'BY_ALL',
  BY_ID: 'BY_ID'
}

export const addToInventoryQuery = (softwareIri) => {
  return `
  INSERT {
    GRAPH ?g {
      ?inv <http://csrc.nist.gov/ns/oscal/common#assets> ${softwareIri}
    } 
  } WHERE {
    GRAPH ?g {
      ?inv a <http://csrc.nist.gov/ns/oscal/common#AssetInventory> 
    }
  }
  `
}

export function getSelectSparqlQuery(queryMode, id, filter, ) {
	let byId = '';
  switch(queryMode){
    case QueryMode.BY_ID:
      byId = byIdClause(id);
      break;
    case QueryMode.BY_ALL:
      break;
    default:
      throw new Error(`Unsupported query mode '${queryMode}'`)
  }

	let filterStr = ''
  return selectQueryForm + byId + predicates + inventoryConstraint + filterStr + '}' ;
}

