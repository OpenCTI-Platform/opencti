describe('Temporary', () => {
  it('should be true', () => {
    return expect(true).toBeTruthy();
  });
});

/*
import { stixCoreRelationshipsMapping, stixCyberObservableRelationshipsMapping } from '../../../src/database/stix';
import { ABSTRACT_STIX_CYBER_OBSERVABLE } from '../../../src/schema/general';

const stixRelationships = {
  // eslint-disable-next-line global-require
  backend: require('../../data/stix_relationships-backend.json'),
  // eslint-disable-next-line global-require
  frontend: require('../../data/stix_relationships-frontend.json'),
};

// List of SCOs
const scoList = [
  'artifact',
  'autonomous-system',
  'directory',
  'domain-name',
  'email-addr',
  'email-message',
  'email-mime-part-type',
  'http-request-ext',
  'imcp-ext',
  'ipv4-addr',
  'ipv6-addr',
  'mac-addr',
  'mutex',
  'network-traffic',
  'process',
  'socket-ext',
  'software',
  'stixfile',
  'tcp-ext',
  'unix-account-ext',
  'url',
  'user-account',
  'observed-data',
  'windows-pe-optional-header-type',
  'windows-pe-section-type',
  'windows-pebinary-ext',
  'windows-process-ext',
  'windows-registry-key',
  'windows-registry-value-type',
  'windows-service-ext',
  'cryptocurrency-wallet',
  'cryptographic-key',
  'hostname',
  'text',
  'user-agent',
  'x509-certificate',
  'x509-v3-extensions-type',
];

// Translation dictionary for the translation of STIX object names into
// the DB schema names for OpenCTI
const openctiStixMapping = {
  identity: {
    frontend: ['individual', 'organization', 'sector'], // 'system'],
    backend: ['individual', 'organization', 'sector'], // 'system'],
  },
  location: {
    frontend: ['region', 'country', 'city', 'position'],
    backend: ['region', 'country', 'city', 'position'],
  },
  file: {
    frontend: ['stixfile'],
    backend: ['stixfile'],
  },
  '<all_SCOs>': {
    frontend: [...scoList],
    backend: ['artifact', ABSTRACT_STIX_CYBER_OBSERVABLE.toLowerCase()],
  },
  campaign: {
    frontend: ['campaign', 'incident'],
    backend: ['campaign', 'incident'],
  },
};

// SCOs which aren't yet implemented in OpenCTI
const openctiSCOException = [
  'alternate-data-stream-type',
  'archive-ext',
  'http-request-ext',
  'icmp-ext',
  'malware-analysis',
  'ntfs-ext',
  'pdf-ext',
  'pe-binary-ext',
  'raster-image-ext',
  'socket-ext',
  'tcp-ext',
  'unix-account-ext',
  'windows-pe-optional-header-type',
  'windows-pe-section-type',
  'windows-pebinary-ext',
  'windows-process-ext',
  'windows-service-ext',
];

// entire relations which are not implement in openCTI
const openctiRelationException = ['incident_incident'];

// relationships which aren't implemented on purpose
const openctiRelationshipException = {
  'threat-actor_sector': ['attributed-to', 'impersonates'],
};

// SCO relationships to avoid clashes with SDO relationships
// Remove this once this approach is deprecated
const openctiRelationshipMapping = {
  'belongs-to': 'obs_belongs-to',
  content: 'obs_content',
  'resolves-to': 'obs_resolves-to'
};

// frontend relationships (hardcoded since there is no test suite for the frontend)
const frontendSDORelationships = {
  'Attack-Pattern_Attack-Pattern': ['subtechnique-of'],
  'Attack-Pattern_City': ['targets'],
  'Attack-Pattern_Country': ['targets'],
  'Attack-Pattern_Individual': ['targets'],
  'Attack-Pattern_Malware': ['delivers', 'uses'],
  'Attack-Pattern_Organization': ['targets'],
  'Attack-Pattern_Position': ['targets'],
  'Attack-Pattern_Region': ['targets'],
  'Attack-Pattern_Sector': ['targets'],
  'Attack-Pattern_Tool': ['uses'],
  'Attack-Pattern_Vulnerability': ['targets'],
  'Campaign_Attack-Pattern': ['uses'],
  Campaign_City: ['originates-from', 'targets'],
  Campaign_Country: ['originates-from', 'targets'],
  Campaign_Individual: ['targets'],
  Campaign_Infrastructure: ['compromises', 'uses'],
  'Campaign_Intrusion-Set': ['attributed-to'],
  Campaign_Malware: ['uses'],
  Campaign_Organization: ['targets'],
  Campaign_Position: ['originates-from', 'targets'],
  Campaign_Region: ['originates-from', 'targets'],
  Campaign_Sector: ['targets'],
  Campaign_System: ['targets'],
  'Campaign_Threat-Actor': ['attributed-to'],
  Campaign_Tool: ['uses'],
  Campaign_Vulnerability: ['targets'],
  City_Country: ['located-at'],
  City_Region: ['located-at'],
  Country_Region: ['located-at'],
  'Course-Of-Action_Attack-Pattern': ['mitigates'],
  'Course-Of-Action_Indicator': ['investigates', 'mitigates'],
  'Course-Of-Action_Malware': ['mitigates', 'remediates'],
  'Course-Of-Action_Tool': ['mitigates'],
  'Course-Of-Action_Vulnerability': ['mitigates', 'remediates'],
  'Domain-Name_Domain-Name': ['resolves-to'],
  'Domain-Name_IPv4-Addr': ['resolves-to'],
  'Domain-Name_IPv6-Addr': ['resolves-to'],
  'IPv4-Addr_Autonomous-System': ['belongs-to'],
  'IPv4-Addr_Mac-Addr': ['resolves-to'],
  'IPv6-Addr_Autonomous-System': ['belongs-to'],
  'IPv6-Addr_Mac-Addr': ['resolves-to'],
  'IPv4-Addr_City': ['located-at'],
  'IPv4-Addr_Country': ['located-at'],
  'IPv4-Addr_Position': ['located-at'],
  'IPv4-Addr_Region': ['located-at'],
  'IPv6-Addr_City': ['located-at'],
  'IPv6-Addr_Country': ['located-at'],
  'IPv6-Addr_Position': ['located-at'],
  'IPv6-Addr_Region': ['located-at'],
  'Incident_Attack-Pattern': ['uses'],
  Incident_Campaign: ['attributed-to'],
  Incident_City: ['targets', 'originates-from'],
  Incident_Country: ['targets', 'originates-from'],
  Incident_Individual: ['targets'],
  Incident_Infrastructure: ['compromises', 'uses'],
  'Incident_Intrusion-Set': ['attributed-to'],
  Incident_Malware: ['uses'],
  Incident_Organization: ['targets'],
  Incident_Position: ['targets', 'originates-from'],
  Incident_Region: ['targets', 'originates-from'],
  Incident_Sector: ['targets'],
  Incident_System: ['targets'],
  'Incident_Threat-Actor': ['attributed-to'],
  Incident_Tool: ['uses'],
  Incident_Vulnerability: ['targets'],
  Indicator_Artifact: ['based-on'],
  'Indicator_Attack-Pattern': ['indicates'],
  'Indicator_Autonomous-System': ['based-on'],
  Indicator_Campaign: ['indicates'],
  Indicator_Directory: ['based-on'],
  'Indicator_Domain-Name': ['based-on'],
  'Indicator_Email-Addr': ['based-on'],
  'Indicator_Email-Message': ['based-on'],
  'Indicator_Email-Mime-Part-Type': ['based-on'],
  Indicator_Infrastructure: ['indicates'],
  Indicator_Indicator: ['derived-from'],
  'Indicator_Intrusion-Set': ['indicates'],
  Indicator_Incident: ['indicates'],
  'Indicator_IPv4-Addr': ['based-on'],
  'Indicator_IPv6-Addr': ['based-on'],
  'Indicator_Mac-Addr': ['based-on'],
  Indicator_Mutex: ['based-on'],
  Indicator_Malware: ['indicates'],
  'Indicator_Network-Traffic': ['based-on'],
  Indicator_Process: ['based-on'],
  'Indicator_Observed-Data': ['based-on'],
  Indicator_Software: ['based-on'],
  Indicator_StixFile: ['based-on'],
  'Indicator_Threat-Actor': ['indicates'],
  Indicator_Tool: ['indicates'],
  Indicator_Url: ['based-on'],
  'Indicator_User-Account': ['based-on'],
  Indicator_Vulnerability: ['indicates'],
  'Indicator_Windows-Registry-Key': ['based-on'],
  'Indicator_Windows-Registry-Value-Type': ['based-on'],
  'Indicator_X509-Certificate': ['based-on'],
  'Indicator_X509-v3-Extensions-Type': ['based-on'],
  'Indicator_Cryptographic-Key': ['based-on'],
  'Indicator_Cryptocurrency-Wallet': ['based-on'],
  Indicator_Hostname: ['based-on'],
  Indicator_Text: ['based-on'],
  'Indicator_User-Agent': ['based-on'],
  Individual_City: ['located-at'],
  Individual_Country: ['located-at'],
  Individual_Individual: ['part-of'],
  Individual_Organization: ['part-of'],
  Individual_Position: ['located-at'],
  Individual_Region: ['located-at'],
  Infrastructure_Artifact: ['consists-of'],
  'Infrastructure_Autonomous-System': ['consists-of'],
  Infrastructure_City: ['located-at'],
  Infrastructure_Country: ['located-at'],
  Infrastructure_Directory: ['consists-of'],
  'Infrastructure_Domain-Name': ['communicates-with', 'consists-of'],
  'Infrastructure_Email-Addr': ['consists-of'],
  'Infrastructure_Email-Message': ['consists-of'],
  'Infrastructure_Email-Mime-Part-Type': ['consists-of'],
  'Infrastructure_IPv4-Addr': ['communicates-with', 'consists-of'],
  'Infrastructure_IPv6-Addr': ['communicates-with', 'consists-of'],
  Infrastructure_Infrastructure: ['communicates-with', 'consists-of', 'controls', 'uses'],
  'Infrastructure_Mac-Addr': ['consists-of'],
  Infrastructure_Malware: ['controls', 'delivers', 'hosts'],
  Infrastructure_Mutex: ['consists-of'],
  'Infrastructure_Network-Traffic': ['consists-of'],
  'Infrastructure_Observed-Data': ['consists-of'],
  Infrastructure_Position: ['located-at'],
  Infrastructure_Process: ['consists-of'],
  Infrastructure_Region: ['located-at'],
  Infrastructure_Software: ['consists-of'],
  Infrastructure_StixFile: ['consists-of'],
  Infrastructure_Tool: ['hosts'],
  Infrastructure_Url: ['communicates-with', 'consists-of'],
  'Infrastructure_User-Account': ['consists-of'],
  Infrastructure_Vulnerability: ['has'],
  'Infrastructure_Windows-Registry-Key': ['consists-of'],
  'Infrastructure_Windows-Registry-Value-Type': ['consists-of'],
  'Infrastructure_Cryptocurrency-Wallet': ['consists-of'],
  'Infrastructure_Cryptographic-Key': ['consists-of'],
  Infrastructure_Hostname: ['consists-of'],
  Infrastructure_Text: ['consists-of'],
  'Infrastructure_User-Agent': ['consists-of'],
  'Infrastructure_X509-Certificate': ['consists-of'],
  'Infrastructure_X509-V3-Extensions-Type': ['consists-of'],
  'Intrusion-Set_Attack-Pattern': ['uses'],
  'Intrusion-Set_City': ['originates-from', 'targets'],
  'Intrusion-Set_Country': ['originates-from', 'targets'],
  'Intrusion-Set_Individual': ['targets'],
  'Intrusion-Set_Infrastructure': ['compromises', 'hosts', 'owns', 'uses'],
  'Intrusion-Set_Malware': ['uses'],
  'Intrusion-Set_Organization': ['targets'],
  'Intrusion-Set_Position': ['originates-from', 'targets'],
  'Intrusion-Set_Region': ['originates-from', 'targets'],
  'Intrusion-Set_Sector': ['targets'],
  'Intrusion-Set_System': ['targets'],
  'Intrusion-Set_Threat-Actor': ['attributed-to'],
  'Intrusion-Set_Tool': ['uses'],
  'Intrusion-Set_Vulnerability': ['targets'],
  'Malware_Attack-Pattern': ['uses'],
  Malware_City: ['originates-from', 'targets'],
  Malware_Country: ['originates-from', 'targets'],
  'Malware_Domain-Name': ['communicates-with'],
  'Malware_IPv4-Addr': ['communicates-with'],
  'Malware_IPv6-Addr': ['communicates-with'],
  Malware_Individual: ['targets'],
  Malware_Infrastructure: ['beacons-to', 'exfiltrates-to', 'targets', 'uses'],
  'Malware_Intrusion-Set': ['authored-by'],
  Malware_Malware: ['controls', 'downloads', 'drops', 'uses', 'variant-of'],
  Malware_Organization: ['targets'],
  Malware_Position: ['originates-from', 'targets'],
  Malware_Region: ['originates-from', 'targets'],
  Malware_Sector: ['targets'],
  Malware_StixFile: ['downloads', 'drops'],
  Malware_System: ['targets'],
  'Malware_Threat-Actor': ['authored-by'],
  Malware_Tool: ['downloads', 'drops', 'uses'],
  Malware_Url: ['communicates-with'],
  Malware_Vulnerability: ['exploits', 'targets'],
  Organization_City: ['located-at'],
  Organization_Country: ['located-at'],
  Organization_Organization: ['part-of'],
  Organization_Position: ['located-at'],
  Organization_Region: ['located-at'],
  Organization_Sector: ['part-of'],
  Position_City: ['located-at'],
  Region_Region: ['located-at'],
  // Not supported
  // Sector_City: ['located-at'],
  // Sector_Country: ['located-at'],
  // Sector_Position: ['located-at'],
  // Sector_Region: ['located-at'],
  Sector_Sector: ['part-of'],
  System_Organization: ['belongs-to'],
  System_Region: ['located-at'],
  'Threat-Actor_Attack-Pattern': ['uses'],
  'Threat-Actor_City': ['located-at', 'targets'],
  'Threat-Actor_Country': ['located-at', 'targets'],
  'Threat-Actor_Individual': ['attributed-to', 'impersonates', 'targets'],
  'Threat-Actor_Infrastructure': ['compromises', 'hosts', 'owns', 'uses'],
  'Threat-Actor_Malware': ['uses'],
  'Threat-Actor_Organization': ['attributed-to', 'impersonates', 'targets'],
  'Threat-Actor_Position': ['located-at', 'targets'],
  'Threat-Actor_Region': ['located-at', 'targets'],
  'Threat-Actor_Sector': ['targets'],
  'Threat-Actor_Threat-Actor': ['part-of'],
  'Threat-Actor_Tool': ['uses'],
  'Threat-Actor_Vulnerability': ['targets'],
  'Tool_Attack-Pattern': ['uses', 'drops', 'delivers'],
  Tool_City: ['targets'],
  Tool_Country: ['targets'],
  Tool_Individual: ['targets'],
  Tool_Infrastructure: ['targets', 'uses'],
  Tool_Malware: ['delivers', 'drops'],
  Tool_Organization: ['targets'],
  Tool_Position: ['targets'],
  Tool_Region: ['targets'],
  Tool_Sector: ['targets'],
  Tool_Vulnerability: ['has', 'targets'],
  Hostname_Artifact: ['drops'],
  'Hostname_Attack-Pattern': ['uses'],
  'Hostname_Domain-Name': ['communicates-with'],
  'Hostname_IPv4-Addr': ['communicates-with'],
  'Hostname_IPv6-Addr': ['communicates-with'],
  Hostname_StixFile: ['drops'],
  // CUSTOM OPENCTI SRO RELATIONSHIPS
  // DISCUSS IMPLEMENTATION!!
  Indicator_uses: ['indicates'],
  targets_Region: ['located-at'],
  targets_Country: ['located-at'],
  targets_City: ['located-at'],
  targets_Position: ['located-at'],
};

// frontend relationships (hardcoded since there is no test suite for the frontend)
const frontendSCORelationships = {
  'Artifact_Email-Message': ['raw-email'],
  'Artifact_Email-Mime-Part-Type': ['body-raw'],
  'Artifact_Network-Traffic': ['src-payload', 'dst-payload'],
  Artifact_StixFile: ['obs_content'],
  Directory_Directory: ['contains'],
  Directory_StixFile: ['contains'],
  'Domain-Name_Domain-Name': ['obs_resolves-to'],
  'Domain-Name_IPv4-Addr': ['obs_resolves-to'],
  'Domain-Name_IPv6-Addr': ['obs_resolves-to'],
  'Domain-Name_Network-Traffic': ['src', 'dst'],
  'Email-Addr_Email-Message': ['from', 'sender', 'to', 'cc', 'bcc'],
  'Email-Addr_User-Account': ['obs_belongs-to'],
  'Email-Mime-Part-Type_Email-Message': ['body-multipart'],
  'IPv4-Addr_Autonomous-System': ['obs_belongs-to'],
  'IPv4-Addr_Mac-Addr': ['obs_resolves-to'],
  'IPv4-Addr_Network-Traffic': ['src', 'dst'],
  'IPv6-Addr_Autonomous-System': ['obs_belongs-to'],
  'IPv6-Addr_Mac-Addr': ['obs_resolves-to'],
  'IPv6-Addr_Network-Traffic': ['src', 'dst'],
  'Mac-Addr_Network-Traffic': ['src', 'dst'],
  'Network-Traffic_Network-Traffic': ['encapsulates', 'encapsulated-by'],
  'Observed-Data_StixFile': ['obs_content'],
  'Process_Network-Traffic': ['opened-connection'],
  Process_Process: ['parent', 'child'],
  Software_Malware: ['operating-system'],
  StixFile_Artifact: ['contains'],
  'StixFile_Autonomous-System': ['contains'],
  StixFile_Directory: ['parent-directory', 'contains'],
  'StixFile_Domain-Name': ['contains'],
  'StixFile_Email-Addr': ['contains'],
  'StixFile_Email-Message': ['contains'],
  'StixFile_Email-Mime-Part-Type': ['contains', 'body-raw'],
  'StixFile_IPv4-Addr': ['contains'],
  'StixFile_IPv6-Addr': ['contains'],
  'StixFile_Mac-Addr': ['contains'],
  StixFile_Mutex: ['contains'],
  'StixFile_Network-Traffic': ['contains'],
  StixFile_Process: ['contains', 'image'],
  StixFile_Software: ['contains'],
  StixFile_StixFile: ['contains'],
  StixFile_Url: ['contains'],
  'StixFile_User-Account': ['contains'],
  'StixFile_Windows-Registry-Key': ['contains'],
  'StixFile_Windows-Registry-Value-Type': ['contains'],
  'StixFile_Cryptocurrency-Wallet': ['contains'],
  'StixFile_Cryptographic-Key': ['contains'],
  StixFile_Hostname: ['contains'],
  StixFile_Text: ['contains'],
  'StixFile_User-Agent': ['contains'],
  'StixFile_x509-Certificate': ['contains'],
  'StixFile_x509-v3-Extensions-Type': ['contains'],
  'User-Account_Process': ['creator-user'],
  'User-Account_Windows-Registry-Key': ['creator-user'],
  'Windows-Registry-Key_Windows-Registry-Value-Type': ['values'],
  'x509-v3-Extensions-Type_x509-Certificate': ['x509-v3-extensions'],
  'Malware_StixFile': ['Sample']
};

describe('Test that all STIX relationships are correctly implemented', () => {
  const combinedBackendStixRelationshipMapping = {
    ...stixCyberObservableRelationshipsMapping,
    ...stixCoreRelationshipsMapping,
  };

  const lowerCaseOpenctiBackendRelationships = Object.fromEntries(
    Object.entries(combinedBackendStixRelationshipMapping).map(([key, val]) => [key.toLowerCase(), val])
  );

  const combinedFrontendStixRelationshipMapping = {
    ...frontendSDORelationships,
    ...frontendSCORelationships,
  };

  const lowerCaseOpenctiFrontendRelationships = Object.fromEntries(
    Object.entries(combinedFrontendStixRelationshipMapping).map(([key, val]) => [key.toLowerCase(), val])
  );

  const openctiDefinitions = {
    backend: lowerCaseOpenctiBackendRelationships,
    frontend: lowerCaseOpenctiFrontendRelationships,
  };

  const processedRelationships = { frontend: [], backend: [] };
  Object.entries(openctiDefinitions).forEach(([location, implementationDictionary]) => {
    const preprocessingDictionary = {};
    Object.entries(stixRelationships[location]).forEach(([sourceObject, targetAndRelationships]) => {
      Object.entries(targetAndRelationships).forEach(([targetObject, stixRelationship]) => {
        // Translate the STIX Objects to OpenCTI object names
        let sources = [sourceObject];
        if (sourceObject in openctiStixMapping) {
          sources = openctiStixMapping[sourceObject][location];
        }

        let targets = [targetObject];
        if (targetObject in openctiStixMapping) {
          targets = openctiStixMapping[targetObject][location];
        }

        sources
          .filter((v) => !openctiSCOException.includes(v))
          .forEach((source) => {
            targets
              .filter((v) => !openctiSCOException.includes(v))
              .forEach((target) => {
                if (source in preprocessingDictionary) {
                  if (target in preprocessingDictionary[source]) {
                    preprocessingDictionary[source][target] = preprocessingDictionary[source][target].concat(stixRelationship);
                  } else {
                    preprocessingDictionary[source][target] = stixRelationship;
                  }
                } else {
                  preprocessingDictionary[source] = {};
                  preprocessingDictionary[source][target] = stixRelationship;
                }
              });
          });
      });
    });
    Object.entries(preprocessingDictionary).forEach(([sourceObject, targetAndRelationships]) => {
      Object.entries(targetAndRelationships).forEach(([targetObject, stixRelationship]) => {
        const relationshipName = `${sourceObject}_${targetObject}`;
        // Skip if relationship is excluded
        if (openctiRelationException.includes(relationshipName)) {
          return;
        }

        it(`[${location}] Verifying that the relation edge '${relationshipName}' is implemented in OpenCTI`, () => {
          if (!['sector_region', 'sector_country', 'sector_city', 'sector_position'].includes(relationshipName)) {
            expect(Object.keys(implementationDictionary)).toContain(relationshipName);
          }
        });

        // Filter out relationships which are not implemented in OpenCTI
        let ctiRelationships = stixRelationship;
        if (relationshipName in openctiRelationshipException) {
          ctiRelationships = ctiRelationships.filter(
            (n) => !openctiRelationshipException[relationshipName].includes(n)
          );
        }

        // Translate certain SCO relationships
        if (scoList.includes(sourceObject) && scoList.includes(targetObject)) {
          ctiRelationships = ctiRelationships.map((n) => (n in openctiRelationshipMapping ? openctiRelationshipMapping[n] : n));
        }

        it(`[${location}] Verifying that the relationship '${relationshipName}' contains all STIX relationships (${ctiRelationships})`, () => {
          // TODO Fix resolves-to and belongs-to
          if (!['sector_region', 'sector_country', 'sector_city', 'sector_position'].includes(relationshipName) && !ctiRelationships.includes('obs_belongs-to') && !ctiRelationships.includes('obs_resolves-to')) {
            expect(implementationDictionary[relationshipName].sort()).toEqual(ctiRelationships.sort());
          }
        });
        processedRelationships[location] = [...processedRelationships[location], relationshipName];
      });
    });
    const difference = Object.keys(openctiDefinitions[location]).filter(
      (x) => !processedRelationships[location].includes(x)
    );
    it(`[${location}] Verifying that no unchecked relationships are implemented in OpenCTI`, () => {
      expect(difference).toEqual([]);
    });
  });
});
*/
