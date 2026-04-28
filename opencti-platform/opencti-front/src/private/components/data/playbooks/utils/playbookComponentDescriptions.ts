const playbookShortDescriptions: Record<string, string> = {
  'listen knowledge events': 'Listen for all platform knowledge events',
  'listen pir events': 'Listen for updates to your PIR(s)',
  'query knowledge on a regular basis': 'Run regular knowledge queries',
  'available for manual enrollment / trigger': 'Use to trigger manual enrollment from any entity in OpenCTI.',
  'match knowledge': 'Match STIX bundle to filter (pass bundle to OUT if filter matches)',
  'reduce knowledge': 'Remove data from STIX bundle that does not match the filter. The main element will always remain.',
  'enrich through connector': 'Use a registered platform connector for enrichment',
  'manipulate knowledge': 'Manipulate STIX bundle according to actions',
  'apply predefined rule': 'Run predefined rule on STIX bundle',
  'promote observable to indicator': 'Create an indicator based on an observable',
  'extract observables from indicator': 'Create observables based on an indicator',
  'container wrapper': 'Create a container and wrap the element inside it',
  'share with organizations': 'Add sharing permissions to the STIX bundle',
  'unshare with organizations': 'Remove sharing permissions to the STIX bundle',
  'manage access restrictions': 'Manage advanced access restrictions to the STIX containers and organisations',
  'remove access restrictions': 'Remove access restrictions to the STIX bundle',
  'send to notifier': 'Automatically send notification',
  'send email from template': 'Automatically send template email',
  'log data in standard output': 'Print bundle in platform logs',
  'send for ingestion': 'Send STIX bundle to knowledge for ingestion',
  'security coverage': 'Create a security coverage for the given entity(ies) (when type is compatible)',
};

const normalizeComponentName = (name: string) => name.trim().toLowerCase().replace(/\s+/g, ' ');

export const getShortComponentDescription = (name?: string | null, fallback?: string | null) => {
  if (!name) return fallback ?? '';
  return playbookShortDescriptions[normalizeComponentName(name)] ?? fallback ?? '';
};
