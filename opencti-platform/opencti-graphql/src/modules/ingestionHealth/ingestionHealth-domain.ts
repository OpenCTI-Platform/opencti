import type { IngestionHealthSettingsInput } from '../../generated/graphql';
import type { AuthContext, AuthUser } from '../../types/user';
import { editSettingsAttribute, readSettingsAttribute } from '../settings/settings-attributes';
import { ingestionHealthSettingsAttribute } from './ingestionHealth-attributes';
import { resolveIngestionHealthSettings, toGraphqlIngestionHealthSettings, validateIngestionHealthSettingsInput } from './ingestionHealth-settings';
import type { IngestionHealthSettings } from './ingestionHealth-types';

const readIngestionHealthSettings = (context: AuthContext, user: AuthUser) => {
  return readSettingsAttribute<IngestionHealthSettings>(context, user, ingestionHealthSettingsAttribute.name);
};

// The settings as used by the manager, absent values replaced by their default
export const getResolvedIngestionHealthSettings = async (context: AuthContext, user: AuthUser) => {
  return resolveIngestionHealthSettings(await readIngestionHealthSettings(context, user));
};

export const getIngestionHealthSettings = async (context: AuthContext, user: AuthUser) => {
  return toGraphqlIngestionHealthSettings(await readIngestionHealthSettings(context, user));
};

export const ingestionHealthSettingsEdit = async (context: AuthContext, user: AuthUser, input: IngestionHealthSettingsInput) => {
  const edited = await editSettingsAttribute<IngestionHealthSettings>(
    context,
    user,
    ingestionHealthSettingsAttribute.name,
    async (current) => {
      await validateIngestionHealthSettingsInput(context, input, current);
      // Validated above: the codes are known ones
      return { ...current, ...input } as IngestionHealthSettings;
    },
    { message: `updates \`${Object.keys(input).join(', ')}\` for \`ingestion health settings\``, input },
  );
  return toGraphqlIngestionHealthSettings(edited);
};
