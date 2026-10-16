import { getMessagesConfigPresetConfiguration } from '../../../domain/settings';
import type { ConfigPresetFamilyDefinition, ConfigPresetItemDefinition } from '../configPreset-types';
import { platformSettingsGroup } from './common-configPreset-registry';

const messagesItem: ConfigPresetItemDefinition = {
  id: 'messages',
  label: 'Messages',
  translatable: true,
  exporter: (context) => getMessagesConfigPresetConfiguration(context),
};

export const messagesFamily: ConfigPresetFamilyDefinition = {
  id: 'messages',
  label: 'Messages',
  group: platformSettingsGroup,
  directory: 'platform_settings',
  listItems: async () => [messagesItem],
};
