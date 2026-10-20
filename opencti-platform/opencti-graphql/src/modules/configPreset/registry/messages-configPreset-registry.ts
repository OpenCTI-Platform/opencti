import type { AuthContext } from '../../../types/user';
import { getMessagesConfigPresetConfigurations } from '../../../domain/settings';
import type { ConfigPresetFamilyDefinition, ConfigPresetItemDefinition } from '../configPreset-types';
import { platformSettingsGroup, staticFamily } from './common-configPreset-registry';

const MESSAGE_LABELS: Record<string, string> = { banner: 'Banner', login: 'Login message', consent: 'Consent message', noAccess: 'No access message' };

const isEmptyConfiguration = (configuration: Record<string, unknown>) => Object.values(configuration).every((value) => value === null || value === '');

// One item per message set on the platform, in platform_settings/messages/; a message that is not set is neither listed nor exported
const getMessagesItems = async (context: AuthContext): Promise<ConfigPresetItemDefinition[]> => {
  const configurations: Record<string, Record<string, unknown>> = await getMessagesConfigPresetConfigurations(context);
  return Object.entries(configurations).filter(([, configuration]) => !isEmptyConfiguration(configuration)).map(([id]) => ({
    id,
    label: MESSAGE_LABELS[id],
    translatable: true,
    fileName: `${id}.json`,
    exporter: async (ctx) => (await getMessagesConfigPresetConfigurations(ctx))[id],
  }));
};

export const messagesFamily: ConfigPresetFamilyDefinition = staticFamily({
  id: 'messages',
  label: 'Messages',
  description: 'Banner, login and consent messages',
  group: platformSettingsGroup,
  directory: 'platform_settings/messages',
}, getMessagesItems);
