import type { DashboardVariable, DashboardVariableRestrictionMode, DashboardVariableType, EditInput, VocabularyCategory } from '../../generated/graphql';
import { fromB64 } from '../../utils/base64';
import { computeDashboardVariablesUsage } from '../dashboard/dashboard-variables-resolution';
import type { StoreDashboardManifest, StoreDashboardVariable } from './workspace-variables-types';

export const buildVariableAuditInput = (
  operation: 'upsert' | 'delete',
  variable: Pick<StoreDashboardVariable, 'id' | 'name' | 'type'>,
): EditInput[] => {
  // Never the manifest: it can be huge and carries every widget definition.
  return [{ key: 'variables', value: [{ operation, id: variable.id, name: variable.name, type: variable.type }] }];
};

export const toGraphqlDashboardVariables = (workspace: { type?: string | null; manifest?: string | null }): DashboardVariable[] => {
  if (workspace.type !== 'dashboard' || !workspace.manifest) return [];
  const manifest = fromB64<StoreDashboardManifest>(workspace.manifest);
  const usage = computeDashboardVariablesUsage(manifest.widgets);
  return (manifest.variables ?? []).map((variable) => {
    const { restriction } = variable;
    return {
      id: variable.id,
      name: variable.name,
      type: variable.type as DashboardVariableType,
      vocabularyCategory: variable.type === 'vocabulary' ? variable.vocabularyCategory as VocabularyCategory : null,
      killChainName: variable.type === 'killChainPhase' ? variable.killChainName : null,
      entityTypes: variable.type === 'entity' ? variable.entityTypes : null,
      restriction: {
        mode: restriction.mode as DashboardVariableRestrictionMode,
        values: restriction.mode === 'selection' ? restriction.values : null,
        filters: restriction.mode === 'filters' ? JSON.stringify(restriction.filters) : null,
      },
      defaultValue: variable.defaultValue,
      usedInWidgetIds: usage.get(variable.id) ?? [],
    };
  });
};
