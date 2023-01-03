import type { BasicStoreCommon, BasicStoreObject } from '../types/store';
import type { AuthContext, AuthUser } from '../types/user';
import type { ListFilter } from '../database/middleware-loader';

export type DomainFindAll<T = BasicStoreObject> = (context: AuthContext, user: AuthUser, args: ListFilter<BasicStoreCommon>) => Promise<T>;
export type DomainFindById<T = BasicStoreObject> = (context: AuthContext, user: AuthUser, id: string, args?: any) => Promise<T>;
export type BatchByIds = (context: AuthContext, user: AuthUser, ids: string[]) => any;
export type CreateEntity<T = BasicStoreObject> = (context: AuthContext, user: AuthUser, input: { objects: never[] }) => Promise<T>;
