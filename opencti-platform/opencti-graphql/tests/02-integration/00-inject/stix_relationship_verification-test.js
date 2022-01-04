import { stixCoreRelationshipsMapping, stixCyberObservableRelationshipsMapping } from '../../../src/database/stix';

const stixRelationships = require('../../data/stix_relationships.json');

const scoList = [
  'artifact',
  'autonomous-system',
  'directory',
  'domain-name',
  'email-addr',
  'email-message',
  'email-message-part-type',
  'file',
  // 'windows-pebinary-ext',
  // 'windows-pe-optional-header-type',
  // 'windows-pe-section-type',
  'ipv4-addr',
  'ipv6-addr',
  'mac-addr',
  'mutex',
  'network-traffic',
  'http-request-ext',
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
];

// TODO adapt test cases for
// Frontend: single implementation
// backend: stix-cyber-observable in general

const openctiStixMapping = {
  identity: ['individual', 'organization', 'sector'],
  location: ['region', 'country', 'city', 'position'],
  file: ['stixfile'],
  // 'observed-data': ['observed-data'],
  '<All STIX Cyber-observable Objects>': ['observed-data'],
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
  'Attack-Pattern_Malware': ['delivers', 'uses'],
  'Attack-Pattern_Sector': ['targets'],
  'Attack-Pattern_Organization': ['targets'],
  'Attack-Pattern_Individual': ['targets'],
  'Attack-Pattern_Region': ['targets'],
  'Attack-Pattern_Country': ['targets'],
  'Attack-Pattern_City': ['targets'],
  'Attack-Pattern_Position': ['targets'],
  'Attack-Pattern_Vulnerability': ['targets'],
  'Attack-Pattern_Tool': ['uses'],
  'Campaign_Intrusion-Set': ['attributed-to'],
  'Campaign_Threat-Actor': ['attributed-to'],
  Campaign_Infrastructure: ['compromises', 'uses'],
  Campaign_Region: ['originates-from', 'targets'],
  Campaign_Country: ['originates-from', 'targets'],
  Campaign_City: ['originates-from', 'targets'],
  Campaign_Position: ['originates-from', 'targets'],
  Campaign_Sector: ['targets'],
  Campaign_System: ['targets'],
  Campaign_Organization: ['targets'],
  Campaign_Individual: ['targets'],
  Campaign_Vulnerability: ['targets'],
  'Campaign_Attack-Pattern': ['uses'],
  Campaign_Malware: ['uses'],
  Campaign_Tool: ['uses'],
  'Course-Of-Action_Indicator': ['investigates', 'mitigates'],
  'Course-Of-Action_Attack-Pattern': ['mitigates'],
  'Course-Of-Action_Malware': ['mitigates', 'remediates'],
  'Course-Of-Action_Tool': ['mitigates'],
  'Course-Of-Action_Vulnerability': ['mitigates', 'remediates'],
  Sector_Region: ['located-at'],
  Sector_Country: ['located-at'],
  Sector_City: ['located-at'],
  Sector_Position: ['located-at'],
  System_Organization: ['belongs-to'],
  Organization_Sector: ['part-of'],
  Organization_Region: ['located-at'],
  Organization_Country: ['located-at'],
  Organization_City: ['located-at'],
  Organization_Position: ['located-at'],
  Organization_Organization: ['part-of'],
  Individual_Organization: ['part-of'],
  Individual_Region: ['located-at'],
  Individual_Country: ['located-at'],
  Individual_City: ['located-at'],
  Individual_Position: ['located-at'],
  'Indicator_Attack-Pattern': ['indicates'],
  Indicator_Campaign: ['indicates'],
  Indicator_Infrastructure: ['indicates'],
  'Indicator_Intrusion-Set': ['indicates'],
  Indicator_Malware: ['indicates'],
  'Indicator_Threat-Actor': ['indicates'],
  Indicator_Tool: ['indicates'],
  'Indicator_Observed-Data': ['based-on'],
  'Indicator_Autonomous-System': ['based-on'],
  Indicator_Directory: ['based-on'],
  'Indicator_Domain-Name': ['based-on'],
  'Indicator_Email-Addr': ['based-on'],
  'Indicator_Email-Messag': ['based-on'],
  'Indicator_Email-Mime-Part-Type': ['based-on'],
  Indicator_Artifact: ['based-on'],
  Indicator_StixFile: ['based-on'],
  'Indicator_X509-Certificate': ['based-on'],
  'Indicator_IPv4-Addr': ['based-on'],
  'Indicator_IPv6-Addr': ['based-on'],
  'Indicator_Mac-Addr': ['based-on'],
  Indicator_Mutex: ['based-on'],
  'Indicator_Network-Traffic': ['based-on'],
  Indicator_Process: ['based-on'],
  Indicator_Software: ['based-on'],
  Indicator_Url: ['based-on'],
  'Indicator_Windows-Registry-Key': ['based-on'],
  'Indicator_Windows-Registry-Value-Type': ['based-on'],
  'Indicator_X509-V3-Extensions-Type': ['based-on'],
  'Indicator_X-OpenCTI-Cryptographic-Key': ['based-on'],
  'Indicator_X-OpenCTI-Cryptocurrency-Wallet': ['based-on'],
  'Indicator_X-OpenCTI-Hostname': ['based-on'],
  'Indicator_X-OpenCTI-Text': ['based-on'],
  'Indicator_X-OpenCTI-User-Agent': ['based-on'],
  Infrastructure_Infrastructure: ['communicates-with', 'consists-of', 'controls', 'uses'],
  'Infrastructure_Observed-Data': ['consists-of'],
  'Infrastructure_Autonomous-System': ['consists-of'],
  Infrastructure_Directory: ['consists-of'],
  'Infrastructure_Domain-Name': ['communicates-with'],
  'Infrastructure_Email-Addr': ['consists-of'],
  'Infrastructure_Email-Message': ['consists-of'],
  'Infrastructure_Email-Mime-Part-Type': ['consists-of'],
  Infrastructure_Artifact: ['consists-of'],
  Infrastructure_StixFile: ['consists-of'],
  'Infrastructure_X509-Certificate': ['consists-of'],
  'Infrastructure_IPv4-Addr': ['communicates-with'],
  'Infrastructure_IPv6-Addr': ['communicates-with'],
  'Infrastructure_Mac-Addr': ['consists-of'],
  Infrastructure_Mutex: ['consists-of'],
  'Infrastructure_Network-Traffic': ['consists-of'],
  Infrastructure_Process: ['consists-of'],
  Infrastructure_Software: ['consists-of'],
  Infrastructure_Url: ['communicates-with'],
  'Infrastructure_User-Account': ['consists-of'],
  'Infrastructure_Windows-Registry-Key': ['consists-of'],
  'Infrastructure_Windows-Registry-Value-Type': ['consists-of'],
  'Infrastructure_X509-V3-Extensions-Type': ['consists-of'],
  'Infrastructure_X-OpenCTI-Cryptographic-Key': ['consists-of'],
  'Infrastructure_X-OpenCTI-Cryptocurrency-Wallet': ['consists-of'],
  'Infrastructure_X-OpenCTI-Hostname': ['consists-of'],
  'Infrastructure_X-OpenCTI-Text': ['consists-of'],
  'Infrastructure_X-OpenCTI-User-Agent': ['consists-of'],
  Infrastructure_Malware: ['controls', 'delivers', 'hosts'],
  Infrastructure_Vulnerability: ['has'],
  Infrastructure_Tool: ['hosts'],
  Infrastructure_Region: ['located-at'],
  Infrastructure_Country: ['located-at'],
  Infrastructure_City: ['located-at'],
  Infrastructure_Position: ['located-at'],
  'Intrusion-Set_Threat-Actor': ['attributed-to'],
  'Intrusion-Set_Infrastructure': ['compromises', 'hosts', 'owns', 'uses'],
  'Intrusion-Set_Region': ['originates-from', 'targets'],
  'Intrusion-Set_Country': ['originates-from', 'targets'],
  'Intrusion-Set_City': ['originates-from', 'targets'],
  'Intrusion-Set_Position': ['originates-from', 'targets'],
  'Intrusion-Set_Sector': ['targets'],
  'Intrusion-Set_Organization': ['targets'],
  'Intrusion-Set_Individual': ['targets'],
  'Intrusion-Set_System': ['targets'],
  'Intrusion-Set_Vulnerability': ['targets'],
  'Intrusion-Set_Attack-Pattern': ['uses'],
  'Intrusion-Set_Malware': ['uses'],
  'Intrusion-Set_Tool': ['uses'],
  'Malware_attack-pattern': ['uses'],
  'Malware_Threat-Actor': ['authored-by'],
  'Malware_Intrusion-Set': ['authored-by'],
  Malware_Infrastructure: ['beacons-to', 'exfiltrates-to', 'targets', 'uses'],
  'Malware_IPv4-Addr': ['communicates-with'],
  'Malware_IPv6-Addr': ['communicates-with'],
  'Malware_Domain-Name': ['communicates-with'],
  Malware_Url: ['communicates-with'],
  Malware_Malware: ['controls', 'downloads', 'drops', 'uses', 'variant-of'],
  Malware_Tool: ['downloads', 'drops', 'uses'],
  Malware_StixFile: ['downloads', 'drops'],
  Malware_Vulnerability: ['exploits', 'targets'],
  Malware_Region: ['originates-from', 'targets'],
  Malware_Country: ['originates-from', 'targets'],
  Malware_City: ['originates-from', 'targets'],
  Malware_Position: ['originates-from', 'targets'],
  Malware_Sector: ['targets'],
  Malware_System: ['targets'],
  Malware_Organization: ['targets'],
  Malware_Individual: ['targets'],
  'Malware_Attack-Pattern': ['uses'],
  Malware_Software: ['operating-system'],
  'Threat-Actor_Organization': ['attributed-to', 'impersonates', 'targets'],
  'Threat-Actor_Individual': ['attributed-to', 'impersonates', 'targets'],
  'Threat-Actor_Sector': ['targets'],
  'Threat-Actor_System': ['targets'],
  'Threat-Actor_Infrastructure': ['compromises', 'hosts', 'owns', 'uses'],
  'Threat-Actor_Region': ['located-at', 'targets'],
  'Threat-Actor_Country': ['located-at', 'targets'],
  'Threat-Actor_City': ['located-at', 'targets'],
  'Threat-Actor_Position': ['located-at', 'targets'],
  'Threat-Actor_Attack-Pattern': ['uses'],
  'Threat-Actor_Malware': ['uses'],
  'Threat-Actor_Threat-Actor': ['part-of'],
  'Threat-Actor_Tool': ['uses'],
  'Threat-Actor_Vulnerability': ['targets'],
  'Tool_Attack-Pattern': ['uses'],
  Tool_Malware: ['delivers', 'drops'],
  Tool_Vulnerability: ['has', 'targets'],
  Tool_Sector: ['targets'],
  Tool_Organization: ['targets'],
  Tool_Individual: ['targets'],
  Tool_Infrastructure: ['targets', 'uses'],
  Tool_Region: ['targets'],
  Tool_Country: ['targets'],
  Tool_City: ['targets'],
  Tool_Position: ['targets'],
  'Incident_Intrusion-Set': ['attributed-to'],
  'Incident_Threat-Actor': ['attributed-to'],
  Incident_Campaign: ['attributed-to'],
  Incident_Infrastructure: ['compromises', 'uses'],
  Incident_Region: ['targets', 'originates-from'],
  Incident_Country: ['targets', 'originates-from'],
  Incident_City: ['targets', 'originates-from'],
  Incident_Position: ['targets', 'originates-from'],
  Incident_Sector: ['targets'],
  Incident_System: ['targets'],
  Incident_Organization: ['targets'],
  Incident_Individual: ['targets'],
  Incident_Vulnerability: ['targets'],
  'Incident_Attack-Pattern': ['uses'],
  Incident_Malware: ['uses'],
  Incident_Tool: ['uses'],
  Country_Region: ['located-at'],
  City_Country: ['located-at'],
  Position_City: ['located-at'],
  'IPv4-Addr_Region': ['located-at'],
  'IPv4-Addr_Country': ['located-at'],
  'IPv4-Addr_City': ['located-at'],
  'IPv4-Addr_Position': ['located-at'],
  'IPv6-Addr_Region': ['located-at'],
  'IPv6-Addr_Country': ['located-at'],
  'IPv6-Addr_City': ['located-at'],
  'IPv6-Addr_Position': ['located-at'],
  targets_City: ['located-at'],
  targets_Country: ['located-at'],
  targets_Region: ['located-at'],
  targets_Position: ['located-at'],
};

// frontend relationships
const frontendStixCyberObservableRelationshipTypesMapping = {
  Directory_Directory: ['contains'],
  Directory_StixFile: ['contains'],
  Directory_Artifact: ['contains'],
  'Email-Addr_User-Account': ['belongs-to'],
  'Email-Message_Email-Addr': ['from', 'sender', 'to', 'cc', 'bcc'],
  'Email-Message_Email-Mime-Part-Type': ['body-multipart'],
  'Email-Message_Artifact': ['raw-email'],
  'Email-Mime-Part-Type_Artifact': ['body-raw'],
  StixFile_Directory: ['parent-directory', 'contains'],
  StixFile_Artifact: ['content'],
  'Domain-Name_Domain-Name': ['resolves-to'],
  'Domain-Name_IPv4-Addr': ['resolves-to'],
  'Domain-Name_IPv6-Addr': ['resolves-to'],
  'IPv4-Addr_Mac-Addr': ['resolves-to'],
  'IPv4-Addr_Autonomous-System': ['belongs-to'],
  'IPv6-Addr_Mac-Addr': ['resolves-to'],
  'IPv6-Addr_Autonomous-System': ['belongs-to'],
  'Network-Traffic_IPv4-Addr': ['src', 'dst'],
  'Network-Traffic_IPv6-Addr': ['src', 'dst'],
  'Network-Traffic_Mac-Addr': ['src', 'dst'],
  'Network-Traffic_Domain-Name': ['src', 'dst'],
  'Network-Traffic_Network-Traffic': ['encapsulates', 'encapsulated-by'],
  'Network-Traffic_Artifact': ['src-payload', 'dst-payload'],
  'Process_Network-Traffic': ['opened-connection'],
  'Process_User-Account': ['creator-user'],
  Process_StixFile: ['image'],
  Process_Process: ['parent', 'child'],
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
  Object.entries(stixRelationships).forEach(([sourceObject, targetAndRelationships]) => {
    Object.entries(targetAndRelationships).forEach(([targetObject, stixRelationship]) => {
      let sources = [sourceObject];
      if (sourceObject in openctiStixMapping) {
        sources = openctiStixMapping[sourceObject];
      }
      let targets = [targetObject];
      if (targetObject in openctiStixMapping) {
        targets = openctiStixMapping[targetObject];
      }

      sources
        .filter((v) => !openctiNotImplementedException.includes(v))
        .forEach((source) => {
          targets
            .filter((v) => !openctiNotImplementedException.includes(v))
            .forEach((target) => {
              const relationshipName = `${source}_${target}`;
              Object.entries(openctiDefinitions).forEach(([location, implementionDictionary]) => {
                it(`[${location}] Verifying that ${relationshipName} is implemented in OpenCTI`, () => {
                  expect(Object.keys(implementionDictionary)).toContain(relationshipName);
                });

                let ctiRelationships = stixRelationship;
                if (relationshipName in openctiRelationshipException) {
                  ctiRelationships = ctiRelationships.filter(
                    (n) => !openctiRelationshipException[relationshipName].includes(n)
                  );
                }
                it(`[${location}] Verifying that ${relationshipName} contains all STIX relationships`, () => {
                  expect(implementionDictionary[relationshipName]).toEqual(ctiRelationships);
                });
                processedRelationships[location] = [...processedRelationships[location], relationshipName];
              });
            });
        });
    });
  });

  it(`Verifying that all STIX Relationships are implemented in OpenCTI`, () => {
    expect(Object.keys(lowerCaseOpenctiBackendRelationships)).toEqual(
      expect.arrayContaining(processedRelationships.backend)
    );
  });

  // console.log(processedRelationships.sort());
  // console.log(Object.keys(lowerCaseOpenctiRelationships).sort());
  // Current result: 135 processed vs 190 implemented ... figure out why
  // it(`Verifying that the OpenCTI relationships contain only STIX relationshsips`, () => {
  //   expect(processedRelationships.length).toEqual(Object.keys(lowerCaseOpenctiRelationship).length);
  // });
});
