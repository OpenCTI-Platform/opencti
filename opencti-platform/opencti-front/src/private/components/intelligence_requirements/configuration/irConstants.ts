// Catalogs offered by the configuration screen of the intelligence requirements proof of concept.

export const IR_ENTITY_TYPES = [
  'Attack-Pattern', 'Campaign', 'Channel', 'Course-Of-Action', 'Event', 'Incident', 'Indicator', 'Infrastructure',
  'Intrusion-Set', 'Malware', 'Narrative', 'Note', 'Report', 'Grouping', 'Threat-Actor-Group', 'Threat-Actor-Individual',
  'Tool', 'Vulnerability', 'Software', 'System', 'Organization', 'Individual', 'Sector', 'Country', 'Region', 'City',
  'Domain-Name', 'IPv4-Addr', 'Url', 'StixFile',
];

export const IR_RELATIONSHIP_TYPES = [
  'uses', 'targets', 'object', 'originates-from', 'exploits', 'indicates', 'variant-of', 'related-to', 'attributed-to', 'has', 'delivers', 'drops',
  'located-at', 'part-of', 'communicates-with', 'compromises', 'impersonates', 'mitigates',
  'remediates', 'belongs-to', 'derived-from', 'authored-by', 'hosts', 'owns', 'beacons-to', 'downloads',
];

export const IR_KEYWORD_FIELDS = ['name', 'description', 'content'];

type Translate = (key: string, values?: { values: Record<string, unknown> }) => string;

// The relationship labels of the platform ("uses", "targets"...), the same as everywhere else in OpenCTI
export const irRelationshipLabel = (t_i18n: Translate, rel: string) => {
  if (rel === 'object') return t_i18n('contains');
  const key = `relationship_${rel}`;
  const label = t_i18n(key);
  return label === key ? rel : label;
};

// The name of a group as shown on screen: its name, never its internal id
export const irGroupLabel = (t_i18n: Translate, groups: readonly { id: string; name: string }[], id: string) => {
  const index = groups.findIndex((g) => g.id === id);
  if (index < 0) return t_i18n('Deleted group');
  // A group saved without a name stores its id as name (draftToInput): it reads as unnamed too
  const name = groups[index].name.trim();
  return name && name !== id ? name : t_i18n('Unnamed group {number}', { values: { number: index + 1 } });
};

// Options of a group picker: the name of the group, never its internal id; a group without a name reads "Unnamed group N"
export const groupSelectOptions = <G extends { id: string; name: string }>(
  t_i18n: Translate,
  groups: readonly G[],
  keep: (group: G) => boolean = () => true,
) => groups.filter(keep).map((g) => ({ value: g.id, label: irGroupLabel(t_i18n, groups, g.id) }));

// Key intelligence questions (KIQ) are set aside in the prototype for now: hidden from every screen.
// The model keeps them (stored KIQs are saved back unchanged), so that they can come back by turning this on.
export const IR_KIQS_ENABLED = false;
