import { BUS_TOPICS } from '../../config/conf';
import { FunctionalError, UnsupportedError } from '../../config/errors';
import { getEntityFromCache } from '../../database/cache';
import { patchAttributeFromLoadedWithRefs, storeLoadByIdWithRefs } from '../../database/middleware';
import { notify } from '../../database/redis';
import { publishUserAction } from '../../listener/UserActionListener';
import type { AttributeDefinition } from '../../schema/attribute-definition';
import { ENTITY_TYPE_SETTINGS } from '../../schema/internalObject';
import { schemaAttributesDefinition } from '../../schema/schema-attributes';
import type { BasicStoreSettings } from '../../types/settings';
import type { StoreEntity } from '../../types/store';
import type { AuthContext, AuthUser } from '../../types/user';

// Attributes of the platform settings owned by a module: the module registers them at bootstrap,
// then reads and writes them through this API only, with its own validation.

const moduleSettingsAttributes = new Set<string>();

const checkModuleSettingsAttribute = (name: string) => {
  if (!moduleSettingsAttributes.has(name)) {
    throw UnsupportedError('Settings attribute not registered by a module', { name });
  }
};

// Not updatable through the generic settings edition: it would skip the validation of the module, even with BYPASS
export const registerSettingsAttribute = (attribute: AttributeDefinition) => {
  moduleSettingsAttributes.add(attribute.name);
  schemaAttributesDefinition.registerAttributes(ENTITY_TYPE_SETTINGS, [{ ...attribute, update: false }]);
};

// From the cached settings: absent until the attribute is first written
export const readSettingsAttribute = async <T>(context: AuthContext, user: AuthUser, name: string): Promise<T | null | undefined> => {
  checkModuleSettingsAttribute(name);
  const settings = await getEntityFromCache<BasicStoreSettings>(context, user, ENTITY_TYPE_SETTINGS);
  return (settings as unknown as Record<string, T | null | undefined>)[name];
};

// The new value is built from the stored one, not the cached one: the module validates its input against it
export const editSettingsAttribute = async <T>(
  context: AuthContext,
  user: AuthUser,
  name: string,
  buildValue: (current: T | null | undefined) => Promise<T>,
  audit: { message: string; input: unknown },
): Promise<T> => {
  checkModuleSettingsAttribute(name);
  const { id } = await getEntityFromCache<BasicStoreSettings>(context, user, ENTITY_TYPE_SETTINGS);
  const settings = await storeLoadByIdWithRefs<StoreEntity>(context, user, id, { type: ENTITY_TYPE_SETTINGS });
  if (!settings) {
    throw FunctionalError('Cant find the platform settings', { id });
  }
  const value = await buildValue((settings as unknown as Record<string, T | null | undefined>)[name]);
  // From the loaded settings: patchAttribute would reject the attribute, not updatable
  const { element } = await patchAttributeFromLoadedWithRefs(context, user, settings, { [name]: value });
  await publishUserAction({
    user,
    event_type: 'mutation',
    event_scope: 'update',
    event_access: 'administration',
    message: audit.message,
    context_data: { id, entity_type: ENTITY_TYPE_SETTINGS, input: audit.input },
  });
  // The settings are read from the cache, reset by this event
  await notify(BUS_TOPICS[ENTITY_TYPE_SETTINGS].EDIT_TOPIC, element, user);
  return (element as unknown as Record<string, T>)[name];
};
