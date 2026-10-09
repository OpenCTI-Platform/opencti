import type { BasicStoreEntity, StoreEntity } from '../../types/store';
import type { AuthorizedMember } from '../../utils/access';

export const ENTITY_TYPE_NOTIFIER = 'Notifier';

export interface BasicStoreEntityNotifier extends BasicStoreEntity {
  internal_id: string;
  name: string;
  description: string;
  built_in: boolean;
  notifier_connector_id: string;
  notifier_configuration: string;
  restricted_members: AuthorizedMember[];
}

export interface StoreEntityNotifier extends StoreEntity {
  name: string;
  description: string;
  built_in: boolean;
  notifier_connector_id: string;
  notifier_configuration: string;
  restricted_members: AuthorizedMember[];
}
