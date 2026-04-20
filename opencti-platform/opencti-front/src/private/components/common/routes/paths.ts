export const PATH_DASHBOARD = '/dashboard';

// TECHNIQUES
export const PATH_ATTACK_PATTERNS = `${PATH_DASHBOARD}/techniques/attack_patterns`;
export const PATH_ATTACK_PATTERN = (attackPatternId: string) => `${PATH_ATTACK_PATTERNS}/${attackPatternId}`;
export const PATH_NARRATIVES = `${PATH_DASHBOARD}/techniques/narratives`;
export const PATH_NARRATIVE = (narrativeId: string) => `${PATH_NARRATIVES}/${narrativeId}`;
export const PATH_DATA_COMPONENTS = `${PATH_DASHBOARD}/techniques/data_components`;
export const PATH_DATA_COMPONENT = (dataComponentId: string) => `${PATH_DATA_COMPONENTS}/${dataComponentId}`;
export const PATH_DATA_SOURCES = `${PATH_DASHBOARD}/techniques/data_sources`;
export const PATH_DATA_SOURCE = (dataSourceId: string) => `${PATH_DATA_SOURCES}/${dataSourceId}`;
export const PATH_COURSES_OF_ACTION = `${PATH_DASHBOARD}/techniques/courses_of_action`;
export const PATH_COURSE_OF_ACTION = (courseOfActionId: string) => `${PATH_COURSES_OF_ACTION}/${courseOfActionId}`;

// ANALYSES
export const PATH_GROUPINGS = `${PATH_DASHBOARD}/analyses/groupings`;
export const PATH_GROUPING = (groupingId: string) => `${PATH_GROUPINGS}/${groupingId}`;
export const PATH_MALWARE_ANALYSES = `${PATH_DASHBOARD}/analyses/malware_analyses`;
export const PATH_MALWARE_ANALYSE = (malwareAnalysisId: string) => `${PATH_MALWARE_ANALYSES}/${malwareAnalysisId}`;
export const PATH_NOTES = `${PATH_DASHBOARD}/analyses/notes`;
export const PATH_NOTE = (noteId: string) => `${PATH_NOTES}/${noteId}`;
export const PATH_REPORTS = `${PATH_DASHBOARD}/analyses/reports`;
export const PATH_REPORT = (reportId: string) => `${PATH_REPORTS}/${reportId}`;
export const PATH_SECURITY_COVERAGES = `${PATH_DASHBOARD}/analyses/security_coverages`;
export const PATH_SECURITY_COVERAGE = (securityCoverageId: string) => `${PATH_SECURITY_COVERAGES}/${securityCoverageId}`;

// ARSENAL
export const PATH_CHANNELS = `${PATH_DASHBOARD}/arsenal/channels`;
export const PATH_CHANNEL = (channelId: string) => `${PATH_CHANNELS}/${channelId}`;
export const PATH_MALWARES = `${PATH_DASHBOARD}/arsenal/malwares`;
export const PATH_MALWARE = (malwareId: string) => `${PATH_MALWARES}/${malwareId}`;
export const PATH_TOOLS = `${PATH_DASHBOARD}/arsenal/tools`;
export const PATH_TOOL = (toolId: string) => `${PATH_TOOLS}/${toolId}`;
export const PATH_VULNERABILITIES = `${PATH_DASHBOARD}/arsenal/vulnerabilities`;
export const PATH_VULNERABILITY = (vulnerabilityId: string) => `${PATH_VULNERABILITIES}/${vulnerabilityId}`;

// LOCATIONS
export const PATH_CITIES = `${PATH_DASHBOARD}/locations/cities`;
export const PATH_CITY = (cityId: string) => `${PATH_CITIES}/${cityId}`;
export const PATH_POSITIONS = `${PATH_DASHBOARD}/locations/positions`;
export const PATH_POSITION = (positionId: string) => `${PATH_POSITIONS}/${positionId}`;
export const PATH_ADMINISTRATIVE_AREAS = `${PATH_DASHBOARD}/locations/administrative_areas`;
export const PATH_ADMINISTRATIVE_AREA = (administrativeAreaId: string) => `${PATH_ADMINISTRATIVE_AREAS}/${administrativeAreaId}`;
export const PATH_REGIONS = `${PATH_DASHBOARD}/locations/regions`;
export const PATH_REGION = (regionId: string) => `${PATH_REGIONS}/${regionId}`;
export const PATH_COUNTRIES = `${PATH_DASHBOARD}/locations/countries`;
export const PATH_COUNTRY = (countryId: string) => `${PATH_COUNTRIES}/${countryId}`;

// OBSERVATIONS
export const PATH_ARTIFACTS = `${PATH_DASHBOARD}/observations/artifacts`;
export const PATH_ARTIFACT = (artifactId: string) => `${PATH_ARTIFACTS}/${artifactId}`;
export const PATH_INFRASTRUCTURES = `${PATH_DASHBOARD}/observations/infrastructures`;
export const PATH_INFRASTRUCTURE = (infrastructureId: string) => `${PATH_INFRASTRUCTURES}/${infrastructureId}`;
export const PATH_INDICATORS = `${PATH_DASHBOARD}/observations/indicators`;
export const PATH_INDICATOR = (indicatorId: string) => `${PATH_INDICATORS}/${indicatorId}`;
export const PATH_OBSERVABLES = `${PATH_DASHBOARD}/observations/observables`;
export const PATH_OBSERVABLE = (observableId: string) => `${PATH_OBSERVABLES}/${observableId}`;

// EVENTS
export const PATH_OBSERVED_DATAS = `${PATH_DASHBOARD}/events/observed_data`;
export const PATH_OBSERVED_DATA = (observedDataId: string) => `${PATH_OBSERVED_DATAS}/${observedDataId}`;
export const PATH_INCIDENTS = `${PATH_DASHBOARD}/events/incidents`;
export const PATH_INCIDENT = (incidentId: string) => `${PATH_INCIDENTS}/${incidentId}`;

// THREATS
export const PATH_THREAT_ACTORS_GROUPS = `${PATH_DASHBOARD}/threats/threat_actors_group`;
export const PATH_THREAT_ACTORS_GROUP = (threatActorGroupId: string) => `${PATH_THREAT_ACTORS_GROUPS}/${threatActorGroupId}`;
export const PATH_THREAT_ACTORS_INDIVIDUALS = `${PATH_DASHBOARD}/threats/threat_actors_individual`;
export const PATH_THREAT_ACTORS_INDIVIDUAL = (threatActorIndividualId: string) => `${PATH_THREAT_ACTORS_INDIVIDUALS}/${threatActorIndividualId}`;
export const PATH_INTRUSION_SETS = `${PATH_DASHBOARD}/threats/intrusion_sets`;
export const PATH_INTRUSION_SET = (intrusionSetId: string) => `${PATH_INTRUSION_SETS}/${intrusionSetId}`;
export const PATH_CAMPAIGNS = `${PATH_DASHBOARD}/threats/campaigns`;
export const PATH_CAMPAIGN = (campaignId: string) => `${PATH_CAMPAIGNS}/${campaignId}`;

// ENTITIES
export const PATH_ORGANIZATIONS = `${PATH_DASHBOARD}/entities/organizations`;
export const PATH_ORGANIZATION = (organizationId: string) => `${PATH_ORGANIZATIONS}/${organizationId}`;
export const PATH_SECURITY_PLATFORMS = `${PATH_DASHBOARD}/entities/security_platforms`;
export const PATH_SECURITY_PLATFORM = (securityPlatformId: string) => `${PATH_SECURITY_PLATFORMS}/${securityPlatformId}`;
export const PATH_SECTORS = `${PATH_DASHBOARD}/entities/sectors`;
export const PATH_SECTOR = (sectorId: string) => `${PATH_SECTORS}/${sectorId}`;
export const PATH_INDIVIDUALS = `${PATH_DASHBOARD}/entities/individuals`;
export const PATH_INDIVIDUAL = (individualId: string) => `${PATH_INDIVIDUALS}/${individualId}`;
export const PATH_EVENTS = `${PATH_DASHBOARD}/entities/events`;
export const PATH_EVENT = (eventId: string) => `${PATH_EVENTS}/${eventId}`;
export const PATH_SYSTEMS = `${PATH_DASHBOARD}/entities/systems`;
export const PATH_SYSTEM = (systemId: string) => `${PATH_SYSTEMS}/${systemId}`;

// CASES
export const PATH_TASKS = `${PATH_DASHBOARD}/cases/tasks`;
export const PATH_TASK = (taskId: string) => `${PATH_TASKS}/${taskId}`;
export const PATH_RFIS = `${PATH_DASHBOARD}/cases/rfis`;
export const PATH_RFI = (rfiId: string) => `${PATH_RFIS}/${rfiId}`;
export const PATH_RFTS = `${PATH_DASHBOARD}/cases/rfts`;
export const PATH_RFT = (rftId: string) => `${PATH_RFTS}/${rftId}`;
export const PATH_FEEDBACKS = `${PATH_DASHBOARD}/cases/feedbacks`;
export const PATH_FEEDBACK = (feedbackId: string) => `${PATH_FEEDBACKS}/${feedbackId}`;
export const PATH_CASE_INCIDENTS = `${PATH_DASHBOARD}/cases/incidents`;
export const PATH_CASE_INCIDENT = (caseIncidentId: string) => `${PATH_CASE_INCIDENTS}/${caseIncidentId}`;
