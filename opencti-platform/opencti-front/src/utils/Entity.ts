export const resolveLink = (type = 'unknown'): string | null => {
  switch (type) {
    case 'Dashboard':
    case 'dashboard': // for using resolveLink in workspaces
      return '/dashboard/workspaces/dashboards';
    case 'Investigation':
    case 'investigation': // for using resolveLink in workspaces
      return '/dashboard/workspaces/investigations';
    case 'Attack-Pattern':
      return '/dashboard/techniques/attack_patterns';
    case 'Campaign':
      return '/dashboard/threats/campaigns';
    case 'Connectors':
      return '/dashboard/data/ingestion/connectors';
    case 'FintelTemplate':
      return '/dashboard/settings/customization/entity_types';
    case 'FintelDesign':
      return '/dashboard/settings/customization/fintel_designs';
    case 'DecayRule':
      return '/dashboard/settings/customization/decay';
    case 'Note':
      return '/dashboard/analyses/notes';
    case 'Security-Coverage':
      return '/dashboard/analyses/security_coverages';
    case 'Observed-Data':
      return '/dashboard/events/observed_data';
    case 'Opinion':
      return '/dashboard/analyses/opinions';
    case 'Playbook':
      return '/dashboard/data/processing/automation';
    case 'Report':
      return '/dashboard/analyses/reports';
    case 'External-Reference':
      return '/dashboard/analyses/external_references';
    case 'Grouping':
      return '/dashboard/analyses/groupings';
    case 'Course-Of-Action':
      return '/dashboard/techniques/courses_of_action';
    case 'Individual':
      return '/dashboard/entities/individuals';
    case 'Organization':
      return '/dashboard/entities/organizations';
    case 'SecurityPlatform':
      return '/dashboard/entities/security_platforms';
    case 'Sector':
      return '/dashboard/entities/sectors';
    case 'System':
      return '/dashboard/entities/systems';
    case 'Event':
      return '/dashboard/entities/events';
    case 'Indicator':
      return '/dashboard/observations/indicators';
    case 'Infrastructure':
      return '/dashboard/observations/infrastructures';
    case 'Intrusion-Set':
      return '/dashboard/threats/intrusion_sets';
    case 'City':
      return '/dashboard/locations/cities';
    case 'Administrative-Area':
      return '/dashboard/locations/administrative_areas';
    case 'Country':
      return '/dashboard/locations/countries';
    case 'Region':
      return '/dashboard/locations/regions';
    case 'Position':
      return '/dashboard/locations/positions';
    case 'Malware':
      return '/dashboard/arsenal/malwares';
    case 'Threat-Actor-Group':
      return '/dashboard/threats/threat_actors_group';
    case 'Threat-Actor-Individual':
      return '/dashboard/threats/threat_actors_individual';
    case 'Tool':
      return '/dashboard/arsenal/tools';
    case 'Channel':
      return '/dashboard/arsenal/channels';
    case 'Narrative':
      return '/dashboard/techniques/narratives';
    case 'Language':
      return '/dashboard/techniques/narratives/languages';
    case 'Vulnerability':
      return '/dashboard/arsenal/vulnerabilities';
    case 'Incident':
      return '/dashboard/events/incidents';
    case 'stix-sighting-relationship':
      return '/dashboard/events/sightings';
    case 'Artifact':
      return '/dashboard/observations/artifacts';
    case 'Data-Component':
      return '/dashboard/techniques/data_components';
    case 'Data-Source':
      return '/dashboard/techniques/data_sources';
    case 'Case-Incident':
      return '/dashboard/cases/incidents';
    case 'Feedback':
      return '/dashboard/cases/feedbacks';
    case 'Case-Rfi':
      return '/dashboard/cases/rfis';
    case 'Case-Rft':
      return '/dashboard/cases/rfts';
    case 'Task':
      return '/dashboard/cases/tasks';
    case 'Malware-Analysis':
      return '/dashboard/analyses/malware_analyses';
    case 'User':
    case 'Creator':
    case 'Assignee':
      return '/dashboard/settings/accesses/users';
    case 'Group':
      return '/dashboard/settings/accesses/groups';
    case 'DraftWorkspace':
      return '/dashboard/data/import/draft';
    case 'Stix-Cyber-Observable':
    case 'Autonomous-System':
    case 'Directory':
    case 'Domain-Name':
    case 'Email-Addr':
    case 'Email-Message':
    case 'Email-Mime-Part-Type':
    case 'StixFile':
    case 'X509-Certificate':
    case 'IPv4-Addr':
    case 'IPv6-Addr':
    case 'Mac-Addr':
    case 'Mutex':
    case 'Network-Traffic':
    case 'Process':
    case 'Software':
    case 'Url':
    case 'User-Account':
    case 'Windows-Registry-Key':
    case 'Windows-Registry-Value-Type':
    case 'Cryptographic-Key':
    case 'Cryptocurrency-Wallet':
    case 'Hostname':
    case 'Text':
    case 'Credential':
    case 'Tracking-Number':
    case 'User-Agent':
    case 'Bank-Account':
    case 'Phone-Number':
    case 'Payment-Card':
    case 'Media-Content':
    case 'Persona':
    case 'IMEI':
    case 'ICCID':
    case 'IMSI':  
      return '/dashboard/observations/observables';
    case 'Pir':
      return '/dashboard/pirs';
    case 'EmailTemplate':
      return '/dashboard/settings/accesses/email_templates';
    case 'SSH-Key':
      return '/dashboard/observations/observables';
    default:
      return null;
  }
};

export const resolveIdentityClass = (identityType: string): string => {
  if (identityType === 'Individual') {
    return 'individual';
  }
  if (identityType === 'Sector') {
    return 'class';
  }
  if (identityType === 'System') {
    return 'system';
  }
  if (identityType === 'SecurityPlatform') {
    return 'securityplatform';
  }
  return 'organization';
};

export const resolveIdentityType = (identityClass: string): string => {
  if (identityClass === 'individual') {
    return 'Individual';
  }
  if (identityClass === 'class') {
    return 'Sector';
  }
  if (identityClass === 'system') {
    return 'System';
  }
  if (identityClass === 'securityplatform') {
    return 'SecurityPlatform';
  }
  return 'Organization';
};

export const resolveLocationType = (entity: Record<string, string>): string => {
  if (entity.x_opencti_location_type) {
    return entity.x_opencti_location_type;
  }
  if (entity.city) {
    return 'City';
  }
  if (entity.country) {
    return 'Country';
  }
  if (entity.region) {
    return 'Region';
  }
  if (entity.area) {
    return 'Administrative-Area';
  }
  return 'Position';
};

export const resolveThreatActorType = (
  entity: Record<string, string>,
): string => {
  if (entity.x_opencti_type) {
    return entity.x_opencti_type;
  }
  if (entity.resource_level === 'individual') {
    return 'Threat-Actor-Individual';
  }
  return 'Threat-Actor-Group';
};

const hashes = ['SHA-512', 'SHA-256', 'SHA-1', 'MD5'];
export const hashValue = (stixCyberObservable: Record<string, never>) => {
  if (stixCyberObservable.hashes) {
    for (let index = 0; index < hashes.length; index += 1) {
      const algo = hashes[index];
      if (stixCyberObservable.hashes[algo]) {
        return stixCyberObservable.hashes[algo];
      }
    }
  }
  return null;
};
// TODO for now this list is duplicated in back, think about updating it aswell
export const observableValue = (stixCyberObservable: Record<string, never>) => {
  switch ((stixCyberObservable.entity_type as string).toLowerCase()) {
    case 'Autonomous-System'.toLowerCase():
      return (
        stixCyberObservable.name || stixCyberObservable.number || 'Unknown'
      );
    case 'Directory'.toLowerCase():
      return stixCyberObservable.path || 'Unknown';
    case 'Email-Message'.toLowerCase():
      return stixCyberObservable.body || stixCyberObservable.subject;
    case 'Artifact'.toLowerCase():
      return (
        hashValue(stixCyberObservable)
        || stixCyberObservable.payload_bin
        || stixCyberObservable.url
        || 'Unknown'
      );
    case 'StixFile'.toLowerCase():
      return (
        hashValue(stixCyberObservable) || stixCyberObservable.name || 'Unknown'
      );
    case 'X509-Certificate'.toLowerCase():
      return (
        hashValue(stixCyberObservable)
        || stixCyberObservable.subject
        || stixCyberObservable.issuer
        || 'Unknown'
      );
    case 'Mutex'.toLowerCase():
      return stixCyberObservable.name || 'Unknown';
    case 'Network-Traffic'.toLowerCase():
      return stixCyberObservable.src_port || stixCyberObservable.dst_port || 'Unknown';
    case 'Process'.toLowerCase():
      return (
        stixCyberObservable.pid || stixCyberObservable.command_line || 'Unknown'
      );
    case 'Software'.toLowerCase():
      return stixCyberObservable.name || stixCyberObservable.cpe || stixCyberObservable.swid || 'Unknown';
    case 'User-Account'.toLowerCase():
      return (
        stixCyberObservable.account_login
        || stixCyberObservable.user_id
        || 'Unknown'
      );
    case 'Bank-Account'.toLowerCase():
      return (
        stixCyberObservable.iban || stixCyberObservable.number || 'Unknown'
      );
    case 'Payment-Card'.toLowerCase():
      return (
        stixCyberObservable.card_number
        || stixCyberObservable.holder_name
        || 'Unknown'
      );
    case 'Windows-Registry-Key'.toLowerCase():
      return stixCyberObservable.attribute_key || 'Unknown';
    case 'Windows-Registry-Value-Type'.toLowerCase():
      return stixCyberObservable.name || stixCyberObservable.data || 'Unknown';
    case 'Media-Content'.toLowerCase():
      return (
        stixCyberObservable.content
        || stixCyberObservable.title
        || stixCyberObservable.url
        || 'Unknown'
      );
    default:
      return stixCyberObservable.value || stixCyberObservable.name || 'Unknown';
  }
};
