import { describe, it, expect } from 'vitest';
import { resolveLink } from './Entity';

describe('Function: resolveLink', () => {
  it('should return URL to SecurityCoverage when type is a SecurityCoverageResult', () => {
    expect(resolveLink('Security-Coverage-Result')).toEqual('/dashboard/analyses/security_coverages');
  });

  it('should return URL to SecurityCoverage when type is Security-Coverage', () => {
    expect(resolveLink('Security-Coverage')).toEqual('/dashboard/analyses/security_coverages');
  });

  // Workspaces
  it('should return URL to dashboards for Dashboard type', () => {
    expect(resolveLink('Dashboard')).toEqual('/dashboard/workspaces/dashboards');
  });

  it('should return URL to dashboards for lowercase dashboard (workspace context)', () => {
    expect(resolveLink('dashboard')).toEqual('/dashboard/workspaces/dashboards');
  });

  it('should return URL to investigations for Investigation type', () => {
    expect(resolveLink('Investigation')).toEqual('/dashboard/workspaces/investigations');
  });

  it('should return URL to investigations for lowercase investigation (workspace context)', () => {
    expect(resolveLink('investigation')).toEqual('/dashboard/workspaces/investigations');
  });

  // Threats
  it('should return URL to campaigns for Campaign type', () => {
    expect(resolveLink('Campaign')).toEqual('/dashboard/threats/campaigns');
  });

  it('should return URL to intrusion sets for Intrusion-Set type', () => {
    expect(resolveLink('Intrusion-Set')).toEqual('/dashboard/threats/intrusion_sets');
  });

  it('should return URL to threat actors group for Threat-Actor-Group type', () => {
    expect(resolveLink('Threat-Actor-Group')).toEqual('/dashboard/threats/threat_actors_group');
  });

  it('should return URL to threat actors individual for Threat-Actor-Individual type', () => {
    expect(resolveLink('Threat-Actor-Individual')).toEqual('/dashboard/threats/threat_actors_individual');
  });

  // Techniques
  it('should return URL to attack patterns for Attack-Pattern type', () => {
    expect(resolveLink('Attack-Pattern')).toEqual('/dashboard/techniques/attack_patterns');
  });

  it('should return URL to courses of action for Course-Of-Action type', () => {
    expect(resolveLink('Course-Of-Action')).toEqual('/dashboard/techniques/courses_of_action');
  });

  it('should return URL to narratives for Narrative type', () => {
    expect(resolveLink('Narrative')).toEqual('/dashboard/techniques/narratives');
  });

  it('should return URL to data components for Data-Component type', () => {
    expect(resolveLink('Data-Component')).toEqual('/dashboard/techniques/data_components');
  });

  it('should return URL to data sources for Data-Source type', () => {
    expect(resolveLink('Data-Source')).toEqual('/dashboard/techniques/data_sources');
  });

  // Analyses
  it('should return URL to reports for Report type', () => {
    expect(resolveLink('Report')).toEqual('/dashboard/analyses/reports');
  });

  it('should return URL to notes for Note type', () => {
    expect(resolveLink('Note')).toEqual('/dashboard/analyses/notes');
  });

  it('should return URL to opinions for Opinion type', () => {
    expect(resolveLink('Opinion')).toEqual('/dashboard/analyses/opinions');
  });

  it('should return URL to groupings for Grouping type', () => {
    expect(resolveLink('Grouping')).toEqual('/dashboard/analyses/groupings');
  });

  it('should return URL to external references for External-Reference type', () => {
    expect(resolveLink('External-Reference')).toEqual('/dashboard/analyses/external_references');
  });

  it('should return URL to malware analyses for Malware-Analysis type', () => {
    expect(resolveLink('Malware-Analysis')).toEqual('/dashboard/analyses/malware_analyses');
  });

  // Arsenal
  it('should return URL to malwares for Malware type', () => {
    expect(resolveLink('Malware')).toEqual('/dashboard/arsenal/malwares');
  });

  it('should return URL to tools for Tool type', () => {
    expect(resolveLink('Tool')).toEqual('/dashboard/arsenal/tools');
  });

  it('should return URL to vulnerabilities for Vulnerability type', () => {
    expect(resolveLink('Vulnerability')).toEqual('/dashboard/arsenal/vulnerabilities');
  });

  it('should return URL to channels for Channel type', () => {
    expect(resolveLink('Channel')).toEqual('/dashboard/arsenal/channels');
  });

  // Events
  it('should return URL to incidents for Incident type', () => {
    expect(resolveLink('Incident')).toEqual('/dashboard/events/incidents');
  });

  it('should return URL to observed data for Observed-Data type', () => {
    expect(resolveLink('Observed-Data')).toEqual('/dashboard/events/observed_data');
  });

  it('should return URL to sightings for stix-sighting-relationship type', () => {
    expect(resolveLink('stix-sighting-relationship')).toEqual('/dashboard/events/sightings');
  });

  // Entities
  it('should return URL to individuals for Individual type', () => {
    expect(resolveLink('Individual')).toEqual('/dashboard/entities/individuals');
  });

  it('should return URL to organizations for Organization type', () => {
    expect(resolveLink('Organization')).toEqual('/dashboard/entities/organizations');
  });

  it('should return URL to sectors for Sector type', () => {
    expect(resolveLink('Sector')).toEqual('/dashboard/entities/sectors');
  });

  it('should return URL to systems for System type', () => {
    expect(resolveLink('System')).toEqual('/dashboard/entities/systems');
  });

  it('should return URL to events for Event type', () => {
    expect(resolveLink('Event')).toEqual('/dashboard/entities/events');
  });

  it('should return URL to security platforms for SecurityPlatform type', () => {
    expect(resolveLink('SecurityPlatform')).toEqual('/dashboard/entities/security_platforms');
  });

  // Locations
  it('should return URL to cities for City type', () => {
    expect(resolveLink('City')).toEqual('/dashboard/locations/cities');
  });

  it('should return URL to countries for Country type', () => {
    expect(resolveLink('Country')).toEqual('/dashboard/locations/countries');
  });

  it('should return URL to regions for Region type', () => {
    expect(resolveLink('Region')).toEqual('/dashboard/locations/regions');
  });

  it('should return URL to positions for Position type', () => {
    expect(resolveLink('Position')).toEqual('/dashboard/locations/positions');
  });

  it('should return URL to administrative areas for Administrative-Area type', () => {
    expect(resolveLink('Administrative-Area')).toEqual('/dashboard/locations/administrative_areas');
  });

  // Observations
  it('should return URL to indicators for Indicator type', () => {
    expect(resolveLink('Indicator')).toEqual('/dashboard/observations/indicators');
  });

  it('should return URL to infrastructures for Infrastructure type', () => {
    expect(resolveLink('Infrastructure')).toEqual('/dashboard/observations/infrastructures');
  });

  it('should return URL to artifacts for Artifact type', () => {
    expect(resolveLink('Artifact')).toEqual('/dashboard/observations/artifacts');
  });

  it('should return URL to observables for IPv4-Addr type', () => {
    expect(resolveLink('IPv4-Addr')).toEqual('/dashboard/observations/observables');
  });

  it('should return URL to observables for Domain-Name type', () => {
    expect(resolveLink('Domain-Name')).toEqual('/dashboard/observations/observables');
  });

  it('should return URL to observables for Url type', () => {
    expect(resolveLink('Url')).toEqual('/dashboard/observations/observables');
  });

  it('should return URL to observables for StixFile type', () => {
    expect(resolveLink('StixFile')).toEqual('/dashboard/observations/observables');
  });

  it('should return URL to observables for generic Stix-Cyber-Observable type', () => {
    expect(resolveLink('Stix-Cyber-Observable')).toEqual('/dashboard/observations/observables');
  });

  // Cases
  it('should return URL to case incidents for Case-Incident type', () => {
    expect(resolveLink('Case-Incident')).toEqual('/dashboard/cases/incidents');
  });

  it('should return URL to feedbacks for Feedback type', () => {
    expect(resolveLink('Feedback')).toEqual('/dashboard/cases/feedbacks');
  });

  it('should return URL to RFIs for Case-Rfi type', () => {
    expect(resolveLink('Case-Rfi')).toEqual('/dashboard/cases/rfis');
  });

  it('should return URL to RFTs for Case-Rft type', () => {
    expect(resolveLink('Case-Rft')).toEqual('/dashboard/cases/rfts');
  });

  it('should return URL to tasks for Task type', () => {
    expect(resolveLink('Task')).toEqual('/dashboard/cases/tasks');
  });

  // Settings
  it('should return URL to users for User type', () => {
    expect(resolveLink('User')).toEqual('/dashboard/settings/accesses/users');
  });

  it('should return URL to users for Creator type', () => {
    expect(resolveLink('Creator')).toEqual('/dashboard/settings/accesses/users');
  });

  it('should return URL to users for Assignee type', () => {
    expect(resolveLink('Assignee')).toEqual('/dashboard/settings/accesses/users');
  });

  it('should return URL to groups for Group type', () => {
    expect(resolveLink('Group')).toEqual('/dashboard/settings/accesses/groups');
  });

  it('should return URL to email templates for EmailTemplate type', () => {
    expect(resolveLink('EmailTemplate')).toEqual('/dashboard/settings/accesses/email_templates');
  });

  it('should return URL to authentications for AuthenticationProvider type', () => {
    expect(resolveLink('AuthenticationProvider')).toEqual('/dashboard/settings/accesses/authentications');
  });

  it('should return URL to entity types customization for FintelTemplate type', () => {
    expect(resolveLink('FintelTemplate')).toEqual('/dashboard/settings/customization/entity_types');
  });

  it('should return URL to fintel designs for FintelDesign type', () => {
    expect(resolveLink('FintelDesign')).toEqual('/dashboard/settings/customization/fintel_designs');
  });

  it('should return URL to decay rules for DecayRule type', () => {
    expect(resolveLink('DecayRule')).toEqual('/dashboard/settings/customization/decay');
  });

  // Other
  it('should return URL to connectors for Connectors type', () => {
    expect(resolveLink('Connectors')).toEqual('/dashboard/data/ingestion/connectors');
  });

  it('should return URL to automation for Playbook type', () => {
    expect(resolveLink('Playbook')).toEqual('/dashboard/data/processing/automation');
  });

  it('should return URL to draft import for DraftWorkspace type', () => {
    expect(resolveLink('DraftWorkspace')).toEqual('/dashboard/data/import/draft');
  });

  it('should return URL to PIRs for Pir type', () => {
    expect(resolveLink('Pir')).toEqual('/dashboard/pirs');
  });

  // Default / unknown
  it('should return null for an unknown type', () => {
    expect(resolveLink('Unknown-Type')).toBeNull();
  });

  it('should return null when called with no argument', () => {
    expect(resolveLink()).toBeNull();
  });
});
