// Common attribute of OCTI added to every entities
// Attributes extensions
// Global = id - type - stix_ids
// Relation = source_ref - source_type - target_ref - target_type
// Sighting = sighting_of_ref - sighting_of_type - where_sighted_refs - where_sighted_types
export const STIX_EXT_OCTI = 'extension-definition--ea279b3e-5c71-4632-ac08-831c66a786ba';

// New SCOs supported by OCTI = CryptocurrencyWallet - CryptographicKey - Hostname - Text
// Attributes extensions
// Global = labels - description
// StixFile =  additional_names
// Artifact = score - additional_names
export const STIX_EXT_OCTI_SCO = 'extension-definition--f93e2c80-4231-4f9a-af8b-95c9bd566a82';

// Extensions from MITRE
// Attributes extensions
// mitre_id
export const STIX_EXT_MITRE = 'extension-definition--322b8f77-262a-4cb8-a915-1e441e00329b';
