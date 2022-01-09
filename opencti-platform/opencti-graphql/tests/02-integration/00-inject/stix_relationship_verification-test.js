import { stixCoreRelationshipsMapping, stixCyberObservableRelationshipsMapping } from '../../../src/database/stix';
import { ABSTRACT_STIX_CYBER_OBSERVABLE } from '../../../src/schema/general';

const stixRelationships = require('../../data/stix_relationships.json');

const scoList = [
  'artifact',
  'autonomous-system',
  'directory',
  'domain-name',
  'email-addr',
  'email-message',
  'email-mime-part-type',
  'stixfile', // file original name
  // 'windows-pebinary-ext',
  // 'windows-pe-optional-header-type',
  // 'windows-pe-section-type',
  'ipv4-addr',
  'ipv6-addr',
  'mac-addr',
  'mutex',
  'network-traffic',
  // 'http-request-ext',
  // 'imcp-ext',
  // 'socket-ext',
  // 'tcp-ext',
  'process',
  // 'windows-process-ext',
  // 'windows-service-ext',
  'url',
  'user-account',
  // 'unix-account-ext',
  'windows-registry-key',
  'windows-registry-value-type',
  'x509-certificate',
  'x509-v3-extensions-type',
  'x-opencti-cryptographic-key',
  'x-opencti-cryptocurrency-wallet',
  'x-opencti-hostname',
  'x-opencti-text',
  'x-opencti-user-agent',
];

const openctiStixMapping = {
  identity: {
    frontend: ['individual', 'organization', 'sector'],
    backend: ['individual', 'organization', 'sector'],
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
    backend: [ABSTRACT_STIX_CYBER_OBSERVABLE.toLowerCase()],
  },
};

// relationships which aren't implemented on purpose
const openctiRelationshipException = {
  'threat-actor_sector': ['attributed-to', 'impersonates'],
};

// SOs which aren't yet implemented in OpenCTI
const openctiNotImplementedException = [
  'malware-analysis',
  'archive-ext',
  'ntfs-ext',
  'alternate-data-stream-type',
  'pdf-ext',
  'raster-image-ext',
];

// frontend relationships
const frontendRelationsTypesMapping = {
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
  'Campaign_City': ['originates-from', 'targets'],
  'Campaign_Country': ['originates-from', 'targets'],
  'Campaign_Individual': ['targets'],
  'Campaign_Infrastructure': ['compromises', 'uses'],
  'Campaign_Intrusion-Set': ['attributed-to'],
  'Campaign_Malware': ['uses'],
  'Campaign_Organization': ['targets'],
  'Campaign_Position': ['originates-from', 'targets'],
  'Campaign_Region': ['originates-from', 'targets'],
  'Campaign_Sector': ['targets'],
  'Campaign_System': ['targets'],
  'Campaign_Threat-Actor': ['attributed-to'],
  'Campaign_Tool': ['uses'],
  'Campaign_Vulnerability': ['targets'],
  'City_Country': ['located-at'],
  'Country_Region': ['located-at'],
  'Course-Of-Action_Attack-Pattern': ['mitigates'],
  'Course-Of-Action_Indicator': ['investigates', 'mitigates'],
  'Course-Of-Action_Malware': ['mitigates', 'remediates'],
  'Course-Of-Action_Tool': ['mitigates'],
  'Course-Of-Action_Vulnerability': ['mitigates', 'remediates'],
  'IPv4-Addr_City': ['located-at'],
  'IPv4-Addr_Country': ['located-at'],
  'IPv4-Addr_Position': ['located-at'],
  'IPv4-Addr_Region': ['located-at'],
  'IPv6-Addr_City': ['located-at'],
  'IPv6-Addr_Country': ['located-at'],
  'IPv6-Addr_Position': ['located-at'],
  'IPv6-Addr_Region': ['located-at'],
  'Incident_Attack-Pattern': ['uses'],
  'Incident_Campaign': ['attributed-to'],
  'Incident_City': ['targets', 'originates-from'],
  'Incident_Country': ['targets', 'originates-from'],
  'Incident_Individual': ['targets'],
  'Incident_Infrastructure': ['compromises', 'uses'],
  'Incident_Intrusion-Set': ['attributed-to'],
  'Incident_Malware': ['uses'],
  'Incident_Organization': ['targets'],
  'Incident_Position': ['targets', 'originates-from'],
  'Incident_Region': ['targets', 'originates-from'],
  'Incident_Sector': ['targets'],
  'Incident_System': ['targets'],
  'Incident_Threat-Actor': ['attributed-to'],
  'Incident_Tool': ['uses'],
  'Incident_Vulnerability': ['targets'],
  'Indicator_Artifact': ['based-on'],
  'Indicator_Attack-Pattern': ['indicates'],
  'Indicator_Autonomous-System': ['based-on'],
  'Indicator_Campaign': ['indicates'],
  'Indicator_Directory': ['based-on'],
  'Indicator_Domain-Name': ['based-on'],
  'Indicator_Email-Addr': ['based-on'],
  'Indicator_Email-Messag': ['based-on'],
  'Indicator_Email-Mime-Part-Type': ['based-on'],
  'Indicator_IPv4-Addr': ['based-on'],
  'Indicator_IPv6-Addr': ['based-on'],
  'Indicator_Infrastructure': ['indicates'],
  'Indicator_Intrusion-Set': ['indicates'],
  'Indicator_Mac-Addr': ['based-on'],
  'Indicator_Malware': ['indicates'],
  'Indicator_Mutex': ['based-on'],
  'Indicator_Network-Traffic': ['based-on'],
  'Indicator_Observed-Data': ['based-on'],
  'Indicator_Process': ['based-on'],
  'Indicator_Software': ['based-on'],
  'Indicator_StixFile': ['based-on'],
  'Indicator_Threat-Actor': ['indicates'],
  'Indicator_Tool': ['indicates'],
  'Indicator_Url': ['based-on'],
  'Indicator_Windows-Registry-Key': ['based-on'],
  'Indicator_Windows-Registry-Value-Type': ['based-on'],
  'Indicator_X-OpenCTI-Cryptocurrency-Wallet': ['based-on'],
  'Indicator_X-OpenCTI-Cryptographic-Key': ['based-on'],
  'Indicator_X-OpenCTI-Hostname': ['based-on'],
  'Indicator_X-OpenCTI-Text': ['based-on'],
  'Indicator_X-OpenCTI-User-Agent': ['based-on'],
  'Indicator_X509-Certificate': ['based-on'],
  'Indicator_X509-V3-Extensions-Type': ['based-on'],
  'Individual_City': ['located-at'],
  'Individual_Country': ['located-at'],
  'Individual_Organization': ['part-of'],
  'Individual_Position': ['located-at'],
  'Individual_Region': ['located-at'],
  'Infrastructure_Artifact': ['consists-of'],
  'Infrastructure_Autonomous-System': ['consists-of'],
  'Infrastructure_City': ['located-at'],
  'Infrastructure_Country': ['located-at'],
  'Infrastructure_Directory': ['consists-of'],
  'Infrastructure_Domain-Name': ['communicates-with', 'consists-of'],
  'Infrastructure_Email-Addr': ['consists-of'],
  'Infrastructure_Email-Message': ['consists-of'],
  'Infrastructure_Email-Mime-Part-Type': ['consists-of'],
  'Infrastructure_IPv4-Addr': ['communicates-with', 'consists-of'],
  'Infrastructure_IPv6-Addr': ['communicates-with', 'consists-of'],
  'Infrastructure_Infrastructure': ['communicates-with', 'consists-of', 'controls', 'uses'],
  'Infrastructure_Mac-Addr': ['consists-of'],
  'Infrastructure_Malware': ['controls', 'delivers', 'hosts'],
  'Infrastructure_Mutex': ['consists-of'],
  'Infrastructure_Network-Traffic': ['consists-of'],
  'Infrastructure_Observed-Data': ['consists-of'],
  'Infrastructure_Position': ['located-at'],
  'Infrastructure_Process': ['consists-of'],
  'Infrastructure_Region': ['located-at'],
  'Infrastructure_Software': ['consists-of'],
  'Infrastructure_StixFile': ['consists-of'],
  'Infrastructure_Tool': ['hosts'],
  'Infrastructure_Url': ['communicates-with', 'consists-of'],
  'Infrastructure_User-Account': ['consists-of'],
  'Infrastructure_Vulnerability': ['has'],
  'Infrastructure_Windows-Registry-Key': ['consists-of'],
  'Infrastructure_Windows-Registry-Value-Type': ['consists-of'],
  'Infrastructure_X-OpenCTI-Cryptocurrency-Wallet': ['consists-of'],
  'Infrastructure_X-OpenCTI-Cryptographic-Key': ['consists-of'],
  'Infrastructure_X-OpenCTI-Hostname': ['consists-of'],
  'Infrastructure_X-OpenCTI-Text': ['consists-of'],
  'Infrastructure_X-OpenCTI-User-Agent': ['consists-of'],
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
  'Malware_Artifact': ['sample'],
  'Malware_Attack-Pattern': ['uses'],
  'Malware_City': ['originates-from', 'targets'],
  'Malware_Country': ['originates-from', 'targets'],
  'Malware_Domain-Name': ['communicates-with'],
  'Malware_IPv4-Addr': ['communicates-with'],
  'Malware_IPv6-Addr': ['communicates-with'],
  'Malware_Individual': ['targets'],
  'Malware_Infrastructure': ['beacons-to', 'exfiltrates-to', 'targets', 'uses'],
  'Malware_Intrusion-Set': ['authored-by'],
  'Malware_Malware': ['controls', 'downloads', 'drops', 'uses', 'variant-of'],
  'Malware_Organization': ['targets'],
  'Malware_Position': ['originates-from', 'targets'],
  'Malware_Region': ['originates-from', 'targets'],
  'Malware_Sector': ['targets'],
  'Malware_Software': ['operating-system'],
  'Malware_StixFile': ['downloads', 'drops', 'sample'],
  'Malware_System': ['targets'],
  'Malware_Threat-Actor': ['authored-by'],
  'Malware_Tool': ['downloads', 'drops', 'uses'],
  'Malware_Url': ['communicates-with'],
  'Malware_Vulnerability': ['exploits', 'targets'],
  'Malware_attack-pattern': ['uses'],
  'Organization_City': ['located-at'],
  'Organization_Country': ['located-at'],
  'Organization_Organization': ['part-of'],
  'Organization_Position': ['located-at'],
  'Organization_Region': ['located-at'],
  'Organization_Sector': ['part-of'],
  'Position_City': ['located-at'],
  'Sector_City': ['located-at'],
  'Sector_Country': ['located-at'],
  'Sector_Position': ['located-at'],
  'Sector_Region': ['located-at'],
  'System_Organization': ['belongs-to'],
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
  'Threat-Actor_System': ['targets'],
  'Threat-Actor_Threat-Actor': ['part-of'],
  'Threat-Actor_Tool': ['uses'],
  'Threat-Actor_Vulnerability': ['targets'],
  'Tool_Attack-Pattern': ['uses'],
  'Tool_City': ['targets'],
  'Tool_Country': ['targets'],
  'Tool_Individual': ['targets'],
  'Tool_Infrastructure': ['targets', 'uses'],
  'Tool_Malware': ['delivers', 'drops'],
  'Tool_Organization': ['targets'],
  'Tool_Position': ['targets'],
  'Tool_Region': ['targets'],
  'Tool_Sector': ['targets'],
  'Tool_Vulnerability': ['has', 'targets'],
};

// frontend relationships
const frontendStixCyberObservableRelationshipTypesMapping = {
  'Directory_Artifact': ['contains'],
  'Directory_Directory': ['contains'],
  'Directory_StixFile': ['contains'],
  'Domain-Name_Domain-Name': ['resolves-to'],
  'Domain-Name_IPv4-Addr': ['resolves-to'],
  'Domain-Name_IPv6-Addr': ['resolves-to'],
  'Email-Addr_User-Account': ['belongs-to'],
  'Email-Message_Artifact': ['raw-email'],
  'Email-Message_Email-Addr': ['from', 'sender', 'to', 'cc', 'bcc'],
  'Email-Message_Email-Mime-Part-Type': ['body-multipart'],
  'Email-Mime-Part-Type_Artifact': ['body-raw'],
  'IPv4-Addr_Autonomous-System': ['belongs-to'],
  'IPv4-Addr_Mac-Addr': ['resolves-to'],
  'IPv6-Addr_Autonomous-System': ['belongs-to'],
  'IPv6-Addr_Mac-Addr': ['resolves-to'],
  'Network-Traffic_Artifact': ['src-payload', 'dst-payload'],
  'Network-Traffic_Domain-Name': ['src', 'dst'],
  'Network-Traffic_IPv4-Addr': ['src', 'dst'],
  'Network-Traffic_IPv6-Addr': ['src', 'dst'],
  'Network-Traffic_Mac-Addr': ['src', 'dst'],
  'Network-Traffic_Network-Traffic': ['encapsulates', 'encapsulated-by'],
  'Process_Network-Traffic': ['opened-connection'],
  'Process_Process': ['parent', 'child'],
  'Process_StixFile': ['image'],
  'Process_User-Account': ['creator-user'],
  'StixFile_Artifact': ['content'],
  'StixFile_Directory': ['parent-directory', 'contains'],
  'StixFile_Domain-Name': ['contains'],
  'Windows-Registry-Key_User-Account': ['creator-user'],
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
    ...frontendRelationsTypesMapping,
    ...frontendStixCyberObservableRelationshipTypesMapping,
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
    Object.entries(stixRelationships).forEach(([sourceObject, targetAndRelationships]) => {
      Object.entries(targetAndRelationships).forEach(([targetObject, stixRelationship]) => {
        let sources = [sourceObject];
        if (sourceObject in openctiStixMapping) {
          sources = openctiStixMapping[sourceObject][location];
        }
        let targets = [targetObject];
        if (targetObject in openctiStixMapping) {
          targets = openctiStixMapping[targetObject][location];
        }

        sources
          .filter((v) => !openctiNotImplementedException.includes(v))
          .forEach((source) => {
            targets
              .filter((v) => !openctiNotImplementedException.includes(v))
              .forEach((target) => {
                const relationshipName = `${source}_${target}`;

                it(`[${location}] Verifying that the relation edge '${relationshipName}' is implemented in OpenCTI`, () => {
                  expect(Object.keys(implementationDictionary)).toContain(relationshipName);
                });

                let ctiRelationships = stixRelationship;
                if (relationshipName in openctiRelationshipException) {
                  ctiRelationships = ctiRelationships.filter(
                    (n) => !openctiRelationshipException[relationshipName].includes(n)
                  );
                }
                it(`[${location}] Verifying that the relationship '${relationshipName}' contains all STIX relationships (${ctiRelationships})`, () => {
                  expect(implementationDictionary[relationshipName].sort()).toEqual(ctiRelationships.sort());
                });
                processedRelationships[location] = [...processedRelationships[location], relationshipName];
              });
          });
      });
    });
  });

  it(`Verifying that all STIX Relationships are implemented in OpenCTI (${
    Object.keys(lowerCaseOpenctiBackendRelationships).length
  }) vs (${processedRelationships.backend.length})`, () => {
    expect(Object.keys(lowerCaseOpenctiBackendRelationships).length).toBeGreaterThanOrEqual(
      processedRelationships.backend.length
    );
  });

  // it(`Verifying that the OpenCTI relationships contain only STIX relationshsips`, () => {
  //   expect(processedRelationships.length).toEqual(Object.keys(lowerCaseOpenctiRelationship).length);
  // });
});
