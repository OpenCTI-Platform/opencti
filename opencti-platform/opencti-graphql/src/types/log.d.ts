import type { StoreConnection, StoreEntity } from './store';

interface Log extends StoreEntity {
  id: string;
}

export type LogConnection = StoreConnection<Log>;
