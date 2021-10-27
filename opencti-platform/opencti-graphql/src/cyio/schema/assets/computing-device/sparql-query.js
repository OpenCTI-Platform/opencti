const selectQueryForm = `
SELECT ?iri ?id
  ?asset_id ?name ?description ?locations
  ?asset_type ?asset_tag ?serial_number ?vendor_name ?version ?release_date
  ?function ?cpe_identifier ?model ?motherboard_id ?installation_id ?installed_hardware ?installed_operating_system 
  ?is_publicly_accessible ?is_scanned ?is_virtual ?bios_id ?fqdn ?hostname ?netbios_name ?network_id ?default_gateway ?vlan_id ?uri ?installed_software ?ip_address ?mac_address ?ports
FROM <tag:stardog:api:context:local>
WHERE {
    ?iri a <http://scap.nist.gov/ns/asset-identification#ComputingDevice> .
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
  # Hardware - ComputingDevice - NetworkDevice
  OPTIONAL { ?iri <http://scap.nist.gov/ns/asset-identification#function> ?function } .
  OPTIONAL { ?iri <http://scap.nist.gov/ns/asset-identification#cpe_identifier> ?cpe_identifier } .
  OPTIONAL { ?iri <http://scap.nist.gov/ns/asset-identification#model> ?model } .
  OPTIONAL { ?iri <http://scap.nist.gov/ns/asset-identification#motherboard_id> ?motherboard_id }
  OPTIONAL { ?iri <http://scap.nist.gov/ns/asset-identification#installation_id> ?installation_id }
  OPTIONAL { ?iri <http://scap.nist.gov/ns/asset-identification#installed_hardware> ?installed_hardware } .
  OPTIONAL { ?iri <http://scap.nist.gov/ns/asset-identification#installed_operating_system> ?installed_operating_system } .
  # ComputingDevice - Server - Workstation
  OPTIONAL { ?iri <http://scap.nist.gov/ns/asset-identification#is_publicly_accessible> ?is_publicly_accessible } .
  OPTIONAL { ?iri <http://scap.nist.gov/ns/asset-identification#is_scanned> ?is_scanned } .
  OPTIONAL { ?iri <http://scap.nist.gov/ns/asset-identification#is_virtual> ?is_virtual } .
  OPTIONAL { ?iri <http://scap.nist.gov/ns/asset-identification#bios_id> ?bios_id }.
  OPTIONAL { ?iri <http://scap.nist.gov/ns/asset-identification#fqdn> ?fqdn } .
  OPTIONAL { ?iri <http://scap.nist.gov/ns/asset-identification#hostname> ?hostname } .
  OPTIONAL { ?iri <http://scap.nist.gov/ns/asset-identification#netbios_name> ?netbios_name } .
  OPTIONAL { ?iri <http://scap.nist.gov/ns/asset-identification#network_id> ?network_id } .
  OPTIONAL { ?iri <http://scap.nist.gov/ns/asset-identification#default_gateway> ?default_gateway } .
  OPTIONAL { ?iri <http://scap.nist.gov/ns/asset-identification#vlan_id> ?vlan_id } .
  OPTIONAL { ?iri <http://scap.nist.gov/ns/asset-identification#uri> ?uri } .
  OPTIONAL { ?iri <http://scap.nist.gov/ns/asset-identification#installed_software> ?installed_software } .
  OPTIONAL { ?iri <http://scap.nist.gov/ns/asset-identification#ip_address> ?ip_address } .
  OPTIONAL { ?iri <http://scap.nist.gov/ns/asset-identification#mac_address> ?mac_address } .
  OPTIONAL { ?iri <http://scap.nist.gov/ns/asset-identification#ports> ?ports } .
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
