import type { BasicConnection, BasicStoreEntity, BasicStoreObject } from '../types/store';
import type { AuthContext, AuthUser } from '../types/user';
import type { EntityOptions } from '../database/middleware-loader';

export type DomainFindPaginated<T extends BasicStoreEntity> = (context: AuthContext, user: AuthUser, args: EntityOptions<T>) => Promise<BasicConnection<T>>;
export type DomainFindById<T = BasicStoreObject> = (context: AuthContext, user: AuthUser, id: string, args?: any) => Promise<T>;
export type BatchByIds = (context: AuthContext, user: AuthUser, ids: string[]) => any;
export type CreateEntity<T = BasicStoreObject> = (context: AuthContext, user: AuthUser, input: { objects: never[] }) => Promise<T>;
