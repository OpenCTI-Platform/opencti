const selectQueryForm = `
SELECT ?iri ?id
  ?asset_id ?name ?description ?locations ?responsible_party 
  ?asset_type ?asset_tag ?serial_number ?vendor_name ?version ?release_date
  ?network_id ?network_name ?network_address_range 
FROM <tag:stardog:api:context:local>
WHERE {
    ?iri a <http://scap.nist.gov/ns/asset-identification#Network> .
`;

const byIdClause = `?iri <http://darklight.ai/ns/common#id> "{id}" .`;

const predicates = `
OPTIONAL { ?iri <http://darklight.ai/ns/common#id> ?id } .
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

export function getSparqlQuery(queryMode, id, filter, ) {
	let byId = '';
	if ( queryMode === 'BY-ID') {
		byId = byIdClause.replace("{id}", id);
	}

	let filterStr = ''
	var sparqlQuery = selectQueryForm + byId + predicates + inventoryConstraint + filterStr + '}'

	return sparqlQuery ;
};