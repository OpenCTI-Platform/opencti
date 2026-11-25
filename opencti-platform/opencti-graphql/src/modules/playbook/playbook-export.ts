import type { AuthContext } from '../../types/user';
import type { BasicStoreEntityPlaybook } from './playbook-types';
import type { PlaybookImportConfiguration } from './playbook-import-schema';
import { exportPlaybookUserReferences, parsePlaybookDefinition } from './playbook-references';

// The definition is exported as is, like the playbook file export: only its users are referenced by standard id
export const exportConfigPresetPlaybook = async (context: AuthContext, playbook: BasicStoreEntityPlaybook): Promise<PlaybookImportConfiguration> => {
  const definition = await exportPlaybookUserReferences(context, parsePlaybookDefinition(playbook.playbook_definition));
  return {
    name: playbook.name,
    description: playbook.description ?? null,
    playbook_start: playbook.playbook_start ?? null,
    playbook_definition: JSON.stringify(definition),
  };
};
