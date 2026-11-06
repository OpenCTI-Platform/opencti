import { useMemo } from 'react';
import type { NormalizedSchema, SchemaPath } from '../../data/schemaTypes';
import { type FindPathOptions, findShortestPath } from './findShortestPath';

export type FindPathResult =
  | { status: 'incomplete' }
  | { status: 'not-found' }
  | { status: 'found'; path: SchemaPath };

export const useFindPath = (schema: NormalizedSchema, fromTypeId: string | null, toTypeId: string | null, options: FindPathOptions): FindPathResult => useMemo(() => {
  if (!fromTypeId || !toTypeId) return { status: 'incomplete' };
  const path = findShortestPath(schema, fromTypeId, toTypeId, options);
  return path ? { status: 'found', path } : { status: 'not-found' };
}, [schema, fromTypeId, toTypeId, options]);
