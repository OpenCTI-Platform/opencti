import * as R from 'ramda';
import type { AuthContext, AuthUser } from '../../types/user';
import type { EditInput } from '../../generated/graphql';
import { fullEntitiesList } from '../../database/middleware-loader';
import { ConfigImportMode, type ConfigImportOptions, type ConfigImportResult } from '../configImport/configImport-types';
import {
  CONFIG_IMPORT_UNCHANGED_REASON,
  configImportReasonValue,
  configImportValidationReason,
  freeConfigImportName,
  joinConfigImportReasons,
} from '../configImport/configImport-utils';
import { sanitizeDefinitionRunAs } from './components/ai-agent-shared';
import { playbookAddFromImport, playbookEdit } from './playbook-domain';
import { type PlaybookImportConfiguration, playbookImportSchema } from './playbook-import-schema';
import { importPlaybookUserReferences, missingPlaybookReferences, parsePlaybookDefinition } from './playbook-references';
import { type BasicStoreEntityPlaybook, type ComponentDefinition, ENTITY_TYPE_PLAYBOOK } from './playbook-types';

export interface PlaybookImportOptions extends ConfigImportOptions {
  reservedNames?: Set<string>;
}

export type PlaybookImportCode = 'invalid' | 'exists' | 'ambiguous' | 'name_conflict' | 'unchanged';

export type PlaybookImportResult = ConfigImportResult<PlaybookImportConfiguration, PlaybookImportCode> & {
  name?: string;
  playbook?: BasicStoreEntityPlaybook;
};

export const AMBIGUOUS_PLAYBOOK_REASON = 'Several playbooks have this name: import it as a copy';

const refused = (code: PlaybookImportCode, reason: string, exists: boolean, configuration?: PlaybookImportConfiguration): PlaybookImportResult => {
  return { status: 'failed', code, reason, exists, configuration };
};

export const findPlaybooks = (context: AuthContext, user: AuthUser) => fullEntitiesList<BasicStoreEntityPlaybook>(context, user, [ENTITY_TYPE_PLAYBOOK]);

const normalizedDefinition = (definition: ComponentDefinition) => ({
  nodes: definition.nodes.map((node) => {
    try {
      return { ...node, configuration: JSON.parse(node.configuration) };
    } catch {
      return node;
    }
  }),
  links: definition.links,
});

const fieldsOf = (configuration: PlaybookImportConfiguration, definition: string) => ({
  description: configuration.description ?? null,
  playbook_start: configuration.playbook_start ?? null,
  playbook_definition: definition,
});

const changedFields = (target: BasicStoreEntityPlaybook, fields: ReturnType<typeof fieldsOf>): EditInput[] => {
  const current = target as unknown as Record<string, unknown>;
  return Object.entries(fields)
    .filter(([key, value]) => {
      if (key === 'playbook_definition') {
        return !R.equals(normalizedDefinition(parsePlaybookDefinition(target.playbook_definition)), normalizedDefinition(parsePlaybookDefinition(value)));
      }
      return (current[key] ?? null) !== value;
    })
    .map(([key, value]) => ({ key, value: [value] }));
};

// overwrite: the playbook of the same name is updated, it keeps its running state. copy: it is created under a free name.
// A created playbook is stopped
export const importConfigPresetPlaybook = async (
  context: AuthContext,
  user: AuthUser,
  configuration: unknown,
  options: PlaybookImportOptions,
): Promise<PlaybookImportResult> => {
  const { mode, dryRun = false, reservedNames } = options;
  const parsed = playbookImportSchema.safeParse(configuration);
  if (!parsed.success) {
    return refused('invalid', configImportValidationReason(parsed.error), false);
  }
  const bundlePlaybook = parsed.data;
  const playbooks = await findPlaybooks(context, user);
  const sameName = playbooks.filter(({ name }) => name === bundlePlaybook.name);
  const exists = sameName.length > 0;
  if (exists && mode === ConfigImportMode.Add) {
    return refused('exists', 'Playbook already exists', true, bundlePlaybook);
  }
  const isCopy = mode === ConfigImportMode.Copy;
  if (!isCopy && (sameName.length > 1 || reservedNames?.has(bundlePlaybook.name))) {
    return refused('ambiguous', AMBIGUOUS_PLAYBOOK_REASON, exists, bundlePlaybook);
  }
  const target = isCopy ? undefined : sameName[0];
  const isNameTaken = async (candidate: string) => !!reservedNames?.has(candidate) || playbooks.some(({ name }) => name === candidate);
  const name = isCopy ? await freeConfigImportName(bundlePlaybook.name, isNameTaken) : bundlePlaybook.name;
  if (!name) {
    return refused('name_conflict', 'Playbook name already exists', exists, bundlePlaybook);
  }
  const { definition, missing: missingUsers } = await importPlaybookUserReferences(context, parsePlaybookDefinition(bundlePlaybook.playbook_definition));
  const playbookDefinition = (await sanitizeDefinitionRunAs(context, user, JSON.stringify(definition))) as string;
  const missingReferences = await missingPlaybookReferences(context, parsePlaybookDefinition(playbookDefinition));
  const fields = fieldsOf(bundlePlaybook, playbookDefinition);
  const reason = joinConfigImportReasons([
    name !== bundlePlaybook.name ? `Added as "${name}"` : undefined,
    missingUsers.length > 0 ? `Users not found: ${configImportReasonValue(missingUsers.join(', '))}` : undefined,
    missingReferences.length > 0 ? `References not found: ${configImportReasonValue(missingReferences.join(', '))}` : undefined,
  ]);
  if (target) {
    const input = changedFields(target, fields);
    if (input.length === 0) {
      return { status: 'skipped', code: 'unchanged', reason: CONFIG_IMPORT_UNCHANGED_REASON, exists: true, name, configuration: bundlePlaybook };
    }
    if (!dryRun) {
      await playbookEdit(context, user, target.id, input);
    }
    return { status: 'overwritten', exists, name, configuration: bundlePlaybook, reason, playbook: target };
  }
  const result: PlaybookImportResult = { status: 'created', exists, name, configuration: bundlePlaybook, reason };
  if (dryRun) {
    return result;
  }
  const created = await playbookAddFromImport(context, user, {
    name,
    description: fields.description,
    playbook_start: fields.playbook_start ?? undefined,
    playbook_definition: fields.playbook_definition,
    playbook_running: false,
  });
  return { ...result, playbook: created as unknown as BasicStoreEntityPlaybook };
};
