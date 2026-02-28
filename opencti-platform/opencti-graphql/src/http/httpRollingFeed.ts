/* eslint-disable camelcase */
import * as R from 'ramda';
import type Express from 'express';
import nconf from 'nconf';
import { TAXIIAPI } from '../domain/user';
import { basePath } from '../config/conf';
import { ForbiddenAccess } from '../config/errors';
import { isUserHasCapability, SYSTEM_USER } from '../utils/access';
import { findById as findFeed } from '../domain/feed';
import { fullEntitiesOrRelationsList } from '../database/middleware';
import { minutesAgo } from '../utils/format';
import { isNotEmptyField } from '../database/utils';
import { convertFiltersToQueryOptions } from '../utils/filtering/filtering-resolution';
import { isMultipleAttribute, isObjectAttribute } from '../schema/schema-attributes';
import { createAuthenticatedContext } from './httpAuthenticatedContext';
import type { BasicStoreBase, BasicStoreEntityFeed, BasicStoreRelation } from '../types/store';
import type { AuthContext, AuthUser } from '../types/user';
import { FilterMode, FilterOperator } from '../generated/graphql';
import { fullRelationsList } from '../database/middleware-loader';
import type { FilterGroupWithNested, FiltersWithNested } from '../database/middleware-loader';
import { elFindByIds } from '../database/engine';
import { READ_RELATIONSHIPS_INDICES } from '../database/utils';

const SIZE_LIMIT = nconf.get('data_sharing:max_csv_feed_result') || 5000;

type NeighborsMap = Map<string, Map<string, BasicStoreBase[]>>;

const errorConverter = (e: any) => {
  const details = R.pipe(R.dissoc('reason'), R.dissoc('http_status'))(e.data);
  return {
    title: e.message,
    error_code: e.name,
    description: e.data?.reason,
    http_status: e.data?.http_status || 500,
    details,
  };
};

const escapeCsvField = (separator: string, data: string) => {
  let escapedData: string;

  if (data.includes('"') || data.includes(separator)
  ) {
    escapedData = data.replaceAll('"', '""');
    return `"${escapedData}"`;
  }
  return data;
};

const neighborKey = (relType: string, targetType: string) => `${relType}:${targetType}`;

const extractAttributeFromEntity = (entity: BasicStoreBase, attributePath: string): string => {
  const isComplexKey = attributePath.includes('.');
  const baseKey = isComplexKey ? attributePath.split('.')[0] : attributePath;
  const data = (entity as any)[baseKey];
  if (!isNotEmptyField(data)) return '';
  if (isComplexKey) {
    const [, innerKey] = attributePath.split('.');
    const dictInnerData = data[innerKey.toUpperCase()];
    return isNotEmptyField(dictInnerData) ? String(dictInnerData) : '';
  }
  if (Array.isArray(data)) return data.join(',');
  if (typeof data === 'object') return JSON.stringify(data);
  return String(data);
};

export const resolveNeighborsForFeed = async (
  context: AuthContext,
  user: AuthUser,
  elements: any[],
  feed: BasicStoreEntityFeed,
): Promise<NeighborsMap> => {
  const neighborsMap: NeighborsMap = new Map();
  const neededPairs = new Set<string>();
  for (const attr of feed.feed_attributes) {
    for (const m of attr.mappings) {
      if (m.relationship_type && m.target_entity_type) {
        neededPairs.add(neighborKey(m.relationship_type, m.target_entity_type));
      }
    }
  }
  if (neededPairs.size === 0) return neighborsMap;

  const elementIds = elements.map((e) => e.internal_id);
  const elementIdSet = new Set(elementIds);

  for (const pairKey of neededPairs) {
    const [relType, targetType] = pairKey.split(':');

    // Query both directions: source entity as FROM, and source entity as TO
    const allRelations: BasicStoreRelation[] = [];

    // Direction 1: feed entities as FROM -> resolve TO neighbors
    const fromFilter: FiltersWithNested = {
      key: ['connections'],
      values: [],
      nested: [
        { key: 'internal_id', values: elementIds },
        { key: 'role', values: ['*_from'], operator: FilterOperator.Wildcard },
      ],
    };
    const toTypeFilter: FiltersWithNested = {
      key: ['connections'],
      values: [],
      nested: [
        { key: 'types', values: [targetType] },
        { key: 'role', values: ['*_to'], operator: FilterOperator.Wildcard },
      ],
    };
    const filtersFrom: FilterGroupWithNested = {
      mode: FilterMode.And,
      filters: [fromFilter, toTypeFilter],
      filterGroups: [],
    };
    const relsFrom = await fullRelationsList<BasicStoreRelation>(context, user, [relType], {
      filters: filtersFrom,
      indices: READ_RELATIONSHIPS_INDICES,
      noFiltersChecking: true,
    });
    allRelations.push(...relsFrom);

    // Direction 2: feed entities as TO -> resolve FROM neighbors
    const toFilter: FiltersWithNested = {
      key: ['connections'],
      values: [],
      nested: [
        { key: 'internal_id', values: elementIds },
        { key: 'role', values: ['*_to'], operator: FilterOperator.Wildcard },
      ],
    };
    const fromTypeFilter: FiltersWithNested = {
      key: ['connections'],
      values: [],
      nested: [
        { key: 'types', values: [targetType] },
        { key: 'role', values: ['*_from'], operator: FilterOperator.Wildcard },
      ],
    };
    const filtersTo: FilterGroupWithNested = {
      mode: FilterMode.And,
      filters: [toFilter, fromTypeFilter],
      filterGroups: [],
    };
    const relsTo = await fullRelationsList<BasicStoreRelation>(context, user, [relType], {
      filters: filtersTo,
      indices: READ_RELATIONSHIPS_INDICES,
      noFiltersChecking: true,
    });
    allRelations.push(...relsTo);

    // Build source->target ID mapping from all found relationships
    const sourceToTargetIds = new Map<string, Set<string>>();
    for (const rel of allRelations) {
      let sourceId: string;
      let targetId: string;
      if (elementIdSet.has(rel.fromId)) {
        sourceId = rel.fromId;
        targetId = rel.toId;
      } else if (elementIdSet.has(rel.toId)) {
        sourceId = rel.toId;
        targetId = rel.fromId;
      } else {
        continue;
      }
      if (!sourceToTargetIds.has(sourceId)) {
        sourceToTargetIds.set(sourceId, new Set());
      }
      sourceToTargetIds.get(sourceId)!.add(targetId);
    }

    // Batch-resolve all target entities
    const allTargetIds = R.uniq(
      Array.from(sourceToTargetIds.values()).flatMap((s) => Array.from(s)),
    );
    if (allTargetIds.length === 0) continue;
    const resolvedEntities = await elFindByIds(context, user, allTargetIds, { type: targetType, toMap: true }) as Record<string, BasicStoreBase>;

    // Populate the neighbors map
    for (const [sourceId, targetIds] of sourceToTargetIds.entries()) {
      if (!neighborsMap.has(sourceId)) {
        neighborsMap.set(sourceId, new Map());
      }
      const entityNeighbors = neighborsMap.get(sourceId)!;
      const resolved: BasicStoreBase[] = [];
      for (const tid of targetIds) {
        const entity = resolvedEntities[tid];
        if (entity) resolved.push(entity);
      }
      const existing = entityNeighbors.get(pairKey) ?? [];
      entityNeighbors.set(pairKey, [...existing, ...resolved]);
    }
  }
  return neighborsMap;
};

export const buildCsvLines = (elements: any[], feed: BasicStoreEntityFeed, neighborsMap?: NeighborsMap): string[] => {
  const lines: string[] = [];
  const separator = feed.separator ?? ',';
  for (let index = 0; index < elements.length; index += 1) {
    const element = elements[index];
    const dataElements = [];
    for (let attrIndex = 0; attrIndex < feed.feed_attributes.length; attrIndex += 1) {
      const attribute = feed.feed_attributes[attrIndex];
      const mapping = attribute.mappings.find((f) => f.type === element.entity_type);
      if (mapping) {
        // Neighbor-based mapping: resolve through relationship
        if (mapping.relationship_type && mapping.target_entity_type) {
          const key = neighborKey(mapping.relationship_type, mapping.target_entity_type);
          const neighbors = neighborsMap?.get(element.internal_id)?.get(key) ?? [];
          if (neighbors.length === 0) {
            dataElements.push(escapeCsvField(separator, ''));
          } else {
            const strategy = attribute.multi_match_strategy ?? 'list';
            const targetEntities = strategy === 'first' ? [neighbors[0]] : neighbors;
            const multiSep = attribute.multi_match_separator ?? ',';
            const values = targetEntities
              .map((n) => extractAttributeFromEntity(n, mapping.attribute))
              .filter((v) => v.length > 0);
            dataElements.push(escapeCsvField(separator, values.join(multiSep)));
          }
        } else {
          // Direct attribute mapping (existing behavior)
          const isComplexKey = mapping.attribute.includes('.');
          const baseKey = isComplexKey ? mapping.attribute.split('.')[0] : mapping.attribute;
          const data = element[baseKey];
          if (isNotEmptyField(data)) {
            if (isMultipleAttribute(element.entity_type, baseKey)) {
              const dataArray = data as string[];
              dataElements.push(escapeCsvField(separator, dataArray.join(',')));
            } else if (isObjectAttribute(baseKey)) {
              if (isComplexKey) {
                const [, innerKey] = mapping.attribute.split('.');
                const dictInnerData = data[innerKey.toUpperCase()];
                if (isNotEmptyField(dictInnerData)) {
                  dataElements.push(escapeCsvField(separator, String(dictInnerData)));
                } else {
                  dataElements.push(escapeCsvField(separator, ''));
                }
              } else {
                dataElements.push(escapeCsvField(separator, JSON.stringify(data)));
              }
            } else {
              dataElements.push(escapeCsvField(separator, String(data)));
            }
          } else {
            dataElements.push(escapeCsvField(separator, ''));
          }
        }
      }
    }

    const line = dataElements.join(separator);
    lines.push(line);
  }
  return lines;
};

const initHttpRollingFeeds = (app: Express.Application) => {
  app.get(`${basePath}/feeds/:id`, async (req: Express.Request, res: Express.Response) => {
    const { id } = req.params as { id: string };
    res.set({ 'content-type': 'text/plain; charset=utf-8' });
    try {
      const context = await createAuthenticatedContext(req, res, 'rolling_feeds');
      const feed = await findFeed(context, SYSTEM_USER, id);
      // The feed doesn't exist at all
      if (!feed) {
        throw ForbiddenAccess();
      }
      // If feed is not public, user must be authenticated
      if (!feed.feed_public && !context.user) {
        throw ForbiddenAccess();
      }
      // If feed is not public, we need to ensure the user access
      if (!feed.feed_public) {
        if (!context.user) {
          throw ForbiddenAccess();
        }
        const userFeed = await findFeed(context, context.user, id);
        if (!isUserHasCapability(context.user, TAXIIAPI) || !userFeed) {
          throw ForbiddenAccess();
        }
      }
      // User is available or feed is public
      const user = context.user ?? SYSTEM_USER;
      const filters = feed.filters ? JSON.parse(feed.filters) : undefined;
      const fromDate = minutesAgo(feed.rolling_time);
      const field = feed.feed_date_attribute ?? 'created_at';
      const extraOptions = { defaultTypes: feed.feed_types, field, orderMode: 'desc', after: fromDate };
      const options = await convertFiltersToQueryOptions(filters, extraOptions);
      const args = { maxSize: SIZE_LIMIT, ...options };
      const paginateElements = await fullEntitiesOrRelationsList(context, user, feed.feed_types, args);
      const elements = R.take(SIZE_LIMIT, paginateElements); // Due to pagination, number of results can be slightly superior
      const neighborsMap = await resolveNeighborsForFeed(context, user, elements, feed);
      if (feed.include_header) {
        res.write(`${feed.feed_attributes.map((a) => a.attribute).join(feed.separator)}\r\n`);
      }

      const lines = buildCsvLines(elements, feed, neighborsMap);
      lines.forEach((l) => {
        res.write(l);
        res.write('\r\n');
      });
      res.send();
    } catch (e) {
      const errorDetail = errorConverter(e);
      res.status(errorDetail.http_status).send(errorDetail);
    }
  });
};

export default initHttpRollingFeeds;
