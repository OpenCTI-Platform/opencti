const selectQueryForm = `

SELECT ?iri ?id ?object_type 
  ?asset_id ?name ?description ?locations ?responsible_party 
  ?asset_type ?asset_tag ?serial_number ?vendor_name ?version ?release_date ?implementation_point ?operational_status
  ?function ?cpe_identifier ?model ?motherboard_id ?installation_id ?installed_hardware ?installed_operating_system ?baseline_configuration_name
  ?is_publicly_accessible ?is_scanned ?is_virtual ?bios_id ?fqdn ?hostname ?network_id ?default_gateway ?vlan_id ?uri ?installed_software ?ip_address ?mac_address ?ports
  ?network_id
  ?network_address_range ?network_name ?service_software
  ?software_identifier ?patch ?license_key
  ?system_name
FROM <tag:stardog:api:context:local>
WHERE {
    ?iri a <http://scap.nist.gov/ns/asset-identification#ItAsset> .
`;

const byIdClause = `?iri <http://darklight.ai/ns/common#id> "{id}" .`;

const predicates = `
	OPTIONAL { ?iri <http://darklight.ai/ns/common#id> ?id } .
	OPTIONAL { ?iri <http://darklight.ai/ns/common#object_type> ?object_type } .
	OPTIONAL { ?iri <http://scap.nist.gov/ns/asset-identification#asset_id> ?asset_id } .
	OPTIONAL { ?iri <http://scap.nist.gov/ns/asset-identification#name> ?name } .
	OPTIONAL { ?iri <http://scap.nist.gov/ns/asset-identification#description> ?description } .
	# OPTIONAL { ?iri <http://scap.nist.gov/ns/asset-identification#locations> ?locations } .
	OPTIONAL { ?iri <http://scap.nist.gov/ns/asset-identification#locations>/<http://scap.nist.gov/ns/asset-identification#name> ?locations } .
	OPTIONAL { ?iri <http://scap.nist.gov/ns/asset-identification#responsible_parties> ?responsible_party } .
	# ItAsset
	OPTIONAL { ?iri <http://scap.nist.gov/ns/asset-identification#asset_type> ?asset_type } .
	OPTIONAL { ?iri <http://scap.nist.gov/ns/asset-identification#asset_tag> ?asset_tag } .
	OPTIONAL { ?iri <http://scap.nist.gov/ns/asset-identification#serial_number> ?serial_number } .
	OPTIONAL { ?iri <http://scap.nist.gov/ns/asset-identification#vendor_name> ?vendor_name }.
	OPTIONAL { ?iri <http://scap.nist.gov/ns/asset-identification#version> ?version } .
	OPTIONAL { ?iri <http://scap.nist.gov/ns/asset-identification#release_date> ?release_date } .
	OPTIONAL { ?iri <http://scap.nist.gov/ns/asset-identification#implementation_point> ?implementation_point } .
	OPTIONAL { ?iri <http://scap.nist.gov/ns/asset-identification#operational_status> ?operational_status } .
	# Hardware - ComputingDevice - NetworkDevice
	OPTIONAL { ?iri <http://scap.nist.gov/ns/asset-identification#function> ?function } .
	OPTIONAL { ?iri <http://scap.nist.gov/ns/asset-identification#cpe_identifier> ?cpe_identifier } .
	OPTIONAL { ?iri <http://scap.nist.gov/ns/asset-identification#model> ?model } .
	OPTIONAL { ?iri <http://scap.nist.gov/ns/asset-identification#motherboard_id> ?motherboard_id }
	OPTIONAL { ?iri <http://scap.nist.gov/ns/asset-identification#installation_id> ?installation_id }
	# OPTIONAL { ?iri <http://scap.nist.gov/ns/asset-identification#installed_hardware> ?installed_hardware } .
	OPTIONAL { ?iri <http://scap.nist.gov/ns/asset-identification#installed_hardware>/<http://scap.nist.gov/ns/asset-identification#name> ?installed_hardware } .
	# OPTIONAL { ?iri <http://scap.nist.gov/ns/asset-identification#installed_operating_system> ?installed_operating_system } .
	OPTIONAL { ?iri <http://scap.nist.gov/ns/asset-identification#installed_operating_system>/<http://scap.nist.gov/ns/asset-identification#name> ?installed_operating_system } .
	OPTIONAL { ?iri <http://scap.nist.gov/ns/asset-identification#baseline_configuration_name> ?baseline_configuration_name } .
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
	# OPTIONAL { ?iri <http://scap.nist.gov/ns/asset-identification#installed_software> ?installed_software } .
	OPTIONAL { ?iri <http://scap.nist.gov/ns/asset-identification#installed_software>/<http://scap.nist.gov/ns/asset-identification#name> ?installed_software } .
	# OPTIONAL { ?iri <http://scap.nist.gov/ns/asset-identification#ip_address> ?ip_address } .
	OPTIONAL { ?iri <http://scap.nist.gov/ns/asset-identification#ip_address>/<http://scap.nist.gov/ns/asset-identification#ip_address_value> ?ip_address } .
	# OPTIONAL { ?iri <http://scap.nist.gov/ns/asset-identification#mac_address> ?mac_address } .
	OPTIONAL { ?iri <http://scap.nist.gov/ns/asset-identification#mac_address>/<http://scap.nist.gov/ns/asset-identification#mac_address_value> ?mac_address } .
	OPTIONAL { ?iri <http://scap.nist.gov/ns/asset-identification#ports> ?ports } .
	# Network Device - Appliance - Firewall - Router - StorageArray - Switch - VoIPHandset - VoIPRouter
	# Network
	OPTIONAL { ?iri <http://scap.nist.gov/ns/asset-identification#network_address_range> ?network_address_range } .
	OPTIONAL { ?iri <http://scap.nist.gov/ns/asset-identification#network_name> ?network_name } .
	# Service
	OPTIONAL { ?iri <http://scap.nist.gov/ns/asset-identification#function> ?function } .
	# OPTIONAL { ?iri <http://scap.nist.gov/ns/asset-identification#service_software> ?service_software } .
	OPTIONAL { ?iri <http://scap.nist.gov/ns/asset-identification#service_software>/<http://scap.nist.gov/ns/asset-identification#name> ?service_software } .
	# Software - OperatingSystem - ApplicationSoftware
	OPTIONAL { ?iri <http://scap.nist.gov/ns/asset-identification#software_identifier> ?software_identifier } .
	OPTIONAL { ?iri <http://scap.nist.gov/ns/asset-identification#patch_level> ?patch } .
	OPTIONAL { ?iri <http://scap.nist.gov/ns/asset-identification#license_key> ?license_key } .
	# System - DirectoryServer - DnsServer - EmailServer - WebServer
	OPTIONAL { ?iri <http://scap.nist.gov/ns/asset-identification#system_name> ?system_name } .
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
