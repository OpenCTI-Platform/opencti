import { STIX_EXT_OCTI } from '../types/stix-2-1-extensions';

type NotificationInstance = { id?: string | null; extensions?: unknown };
type OctiExtensions = Record<string, { id?: string | null } | undefined>;

// Notification links (/dashboard/id/<id>) must use the internal id of the entity, which never changes.
// A STIX instance carries its standard id in `id`, and that id is regenerated when a contributing
// attribute changes (a rename for example), so a link built on it breaks after the edit.
export const resolveNotificationInstanceId = (instance: NotificationInstance): string | null | undefined => {
  const extensions = instance.extensions as OctiExtensions | undefined;
  return extensions?.[STIX_EXT_OCTI]?.id ?? instance.id;
};
