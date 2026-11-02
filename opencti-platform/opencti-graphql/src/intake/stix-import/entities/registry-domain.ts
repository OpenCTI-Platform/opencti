import { importAttackPattern } from './attack-pattern';
import { importCampaign } from './campaign';
import { importChannel } from './channel';
import type { StixImporter } from '../kwargs';
import { importCourseOfAction } from './course-of-action';
import { importDataComponent } from './data-component';
import { importDataSource } from './data-source';
import { importEvent } from './event';
import { importIdentity } from './identity';
import { importIncident } from './incident';
import { importInfrastructure } from './infrastructure';
import { importIntrusionSet } from './intrusion-set';
import { importLanguage } from './language';
import { importLocation } from './location';
import { importMalware } from './malware';
import { importMalwareAnalysis } from './malware-analysis';
import { importMarkingDefinition } from './marking-definition';
import { importNarrative } from './narrative';
import { importSecurityCoverage } from './security-coverage';
import { importSecurityCoverageResult } from './security-coverage-result';
import { importThreatActor } from './threat-actor';
import { importTool } from './tool';
import { importVulnerability } from './vulnerability';

// Importers of the domain objects (threats, arsenal, techniques, identities, locations...),
// keyed by STIX type as in pycti get_stix_helper, aliases included
export const DOMAIN_IMPORTERS: Record<string, StixImporter> = {
  'attack-pattern': importAttackPattern,
  campaign: importCampaign,
  'course-of-action': importCourseOfAction,
  identity: importIdentity,
  infrastructure: importInfrastructure,
  'intrusion-set': importIntrusionSet,
  location: importLocation,
  malware: importMalware,
  'threat-actor': importThreatActor,
  tool: importTool,
  vulnerability: importVulnerability,
  incident: importIncident,
  'x-opencti-incident': importIncident,
  'marking-definition': importMarkingDefinition,
  channel: importChannel,
  'data-component': importDataComponent,
  'x-mitre-data-component': importDataComponent,
  'data-source': importDataSource,
  'x-mitre-data-source': importDataSource,
  event: importEvent,
  language: importLanguage,
  'malware-analysis': importMalwareAnalysis,
  narrative: importNarrative,
  'security-coverage': importSecurityCoverage,
  'security-coverage-result': importSecurityCoverageResult,
};
