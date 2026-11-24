import type { AuthContext } from '../../types/user';
import type { BasicStoreObject } from '../../types/store';
import { internalFindByIdsMapped } from '../../database/middleware-loader';
import { SYSTEM_USER } from '../../utils/access';
import { ENTITY_TYPE_USER } from '../../schema/internalObject';
import { OPENCTI_ADMIN_UUID } from '../../schema/general';
import { isInternalId } from '../../schema/schemaUtils';
import { STATIC_NOTIFIER_EMAIL, STATIC_NOTIFIER_UI } from '../notifier/notifier-statics';
import type { ComponentDefinition, NodeDefinition } from './playbook-types';

type Option = { label?: unknown; value?: unknown };
type NodeConfiguration = Record<string, unknown> & { run_as?: string | Option | null };

const PORTABLE_IDS = new Set([OPENCTI_ADMIN_UUID, STATIC_NOTIFIER_UI, STATIC_NOTIFIER_EMAIL]);

const MEMBER_FIELDS = ['access_restrictions', 'authorized_members', 'targets'];

const USER_STANDARD_ID_PREFIX = 'user--';

export interface PlaybookReference {
  id: string;
  label: string;
}

const parseConfiguration = (node: NodeDefinition): NodeConfiguration | undefined => {
  try {
    const configuration = JSON.parse(node.configuration);
    return configuration && typeof configuration === 'object' ? configuration : undefined;
  } catch {
    return undefined;
  }
};

export const parsePlaybookDefinition = (playbookDefinition: string | null | undefined): ComponentDefinition => {
  try {
    const definition = JSON.parse(playbookDefinition ?? '');
    return { nodes: Array.isArray(definition?.nodes) ? definition.nodes : [], links: Array.isArray(definition?.links) ? definition.links : [] };
  } catch {
    return { nodes: [], links: [] };
  }
};

const optionReference = (option: unknown): PlaybookReference | undefined => {
  if (typeof option === 'string') {
    return { id: option, label: option };
  }
  const { value, label } = (option ?? {}) as Option;
  return typeof value === 'string' ? { id: value, label: typeof label === 'string' && label ? label : value } : undefined;
};

const nodeUserReferences = (configuration: NodeConfiguration): PlaybookReference[] => {
  const runAs = optionReference(configuration.run_as);
  const members = MEMBER_FIELDS.flatMap((field) => {
    const options = configuration[field];
    return Array.isArray(options) ? options.map(optionReference) : [];
  });
  return [runAs, ...members].filter((reference): reference is PlaybookReference => !!reference);
};

export const playbookUserReferences = (definition: ComponentDefinition): PlaybookReference[] => {
  return definition.nodes.flatMap((node) => {
    const configuration = parseConfiguration(node);
    return configuration ? nodeUserReferences(configuration) : [];
  });
};

const replaceOption = (option: unknown, replacements: Map<string, string | null>) => {
  const reference = optionReference(option);
  if (!reference || !replacements.has(reference.id)) {
    return option;
  }
  const replacement = replacements.get(reference.id) ?? null;
  if (replacement === null) {
    return null;
  }
  return typeof option === 'string' ? replacement : { ...(option as Option), value: replacement };
};

// Replaces the user references of the definition; a member whose replacement is null is removed.
// A run_as is never removed: the import resets the one it cannot resolve to the importing user
export const replacePlaybookUserReferences = (definition: ComponentDefinition, replacements: Map<string, string | null>): ComponentDefinition => ({
  ...definition,
  nodes: definition.nodes.map((node) => {
    const configuration = parseConfiguration(node);
    if (!configuration || !nodeUserReferences(configuration).some(({ id }) => replacements.has(id))) {
      return node;
    }
    const replaced: NodeConfiguration = { ...configuration };
    if (configuration.run_as !== undefined && configuration.run_as !== null) {
      replaced.run_as = (replaceOption(configuration.run_as, replacements) ?? configuration.run_as) as NodeConfiguration['run_as'];
    }
    MEMBER_FIELDS.forEach((field) => {
      const options = configuration[field];
      if (Array.isArray(options)) {
        replaced[field] = options.map((option) => replaceOption(option, replacements)).filter((option) => option !== null);
      }
    });
    return { ...node, configuration: JSON.stringify(replaced) };
  }),
});

export const exportPlaybookUserReferences = async (context: AuthContext, definition: ComponentDefinition) => {
  const ids = [...new Set(playbookUserReferences(definition).map(({ id }) => id))].filter((id) => isInternalId(id) && !PORTABLE_IDS.has(id));
  if (ids.length === 0) {
    return definition;
  }
  const users = await internalFindByIdsMapped<BasicStoreObject>(context, SYSTEM_USER, ids, { type: ENTITY_TYPE_USER, baseData: true });
  const replacements = new Map(ids.filter((id) => users[id]).map((id) => [id, users[id].standard_id]));
  return replacePlaybookUserReferences(definition, replacements);
};

const accessRestrictionsOf = (node: NodeDefinition) => {
  const restrictions = parseConfiguration(node)?.access_restrictions;
  return Array.isArray(restrictions) ? restrictions : [];
};

// Without its members, an access restriction node would let the data through unrestricted
const emptiedAccessRestrictions = (before: ComponentDefinition, after: ComponentDefinition) => before.nodes
  .filter((node, index) => accessRestrictionsOf(node).length > 0 && accessRestrictionsOf(after.nodes[index]).length === 0)
  .map((node) => node.name || node.id);

export const importPlaybookUserReferences = async (context: AuthContext, definition: ComponentDefinition) => {
  const references = playbookUserReferences(definition).filter(({ id }) => id.startsWith(USER_STANDARD_ID_PREFIX));
  const ids = [...new Set(references.map(({ id }) => id))];
  if (ids.length === 0) {
    return { definition, missing: [], emptiedAccessRestrictions: [] };
  }
  const users = await internalFindByIdsMapped<BasicStoreObject>(context, SYSTEM_USER, ids, { type: ENTITY_TYPE_USER, baseData: true, mapWithAllIds: true });
  const replacements = new Map(ids.map((id) => [id, users[id]?.internal_id ?? null]));
  const missing = [...new Set(references.filter(({ id }) => !users[id]).map(({ label }) => label))];
  const imported = replacePlaybookUserReferences(definition, replacements);
  return { definition: imported, missing, emptiedAccessRestrictions: emptiedAccessRestrictions(definition, imported) };
};

const parseJsonObject = (value: string): unknown => {
  if (!value.startsWith('{') && !value.startsWith('[')) {
    return undefined;
  }
  try {
    return JSON.parse(value);
  } catch {
    return undefined;
  }
};

const collectIds = (value: unknown, references: Map<string, string>, depth = 0) => {
  if (depth > 32 || value === null || value === undefined) {
    return;
  }
  if (typeof value === 'string') {
    if (isInternalId(value)) {
      if (!references.has(value)) references.set(value, value);
      return;
    }
    const parsed = parseJsonObject(value);
    if (parsed !== undefined) collectIds(parsed, references, depth + 1);
    return;
  }
  if (Array.isArray(value)) {
    value.forEach((child) => collectIds(child, references, depth + 1));
    return;
  }
  if (typeof value === 'object') {
    const { value: optionValue, label } = value as Option;
    if (typeof optionValue === 'string' && isInternalId(optionValue) && typeof label === 'string' && label) {
      references.set(optionValue, label);
    }
    Object.values(value).forEach((child) => collectIds(child, references, depth + 1));
  }
};

// The definition is imported as is: an id the platform does not have stays in it (the node does not do its work until it is set again), and is reported
export const missingPlaybookReferences = async (context: AuthContext, definition: ComponentDefinition): Promise<string[]> => {
  const references = new Map<string, string>();
  definition.nodes.forEach((node) => collectIds(parseConfiguration(node), references));
  PORTABLE_IDS.forEach((id) => references.delete(id));
  const ids = [...references.keys()];
  if (ids.length === 0) {
    return [];
  }
  const found = await internalFindByIdsMapped<BasicStoreObject>(context, SYSTEM_USER, ids, { baseData: true, mapWithAllIds: true });
  return [...new Set(ids.filter((id) => !found[id]).map((id) => references.get(id) as string))];
};
