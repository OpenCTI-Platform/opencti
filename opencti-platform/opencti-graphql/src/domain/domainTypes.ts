import type { BasicStoreEntity, BasicStoreObject, StoreEntityConnection } from '../types/store';
import type { AuthContext, AuthUser } from '../types/user';
import type { EntityOptions } from '../database/middleware-loader';

export type DomainFindAll<T extends BasicStoreEntity> = (context: AuthContext, user: AuthUser, args: EntityOptions<T>) => Promise<StoreEntityConnection<T>>;
export type DomainFindById<T = BasicStoreObject> = (context: AuthContext, user: AuthUser, id: string, args?: any) => Promise<T>;
export type BatchByIds = (context: AuthContext, user: AuthUser, ids: string[]) => any;
export type CreateEntity<T = BasicStoreObject> = (context: AuthContext, user: AuthUser, input: { objects: never[] }) => Promise<T>;
