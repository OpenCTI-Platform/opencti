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
import type { BasicStoreEntityFeed } from '../types/store';

const SIZE_LIMIT = nconf.get('data_sharing:max_csv_feed_result') || 5000;

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
  let escapedData:string;

  if (data.includes('"') || data.includes(separator)
  ) {
    escapedData = data.replaceAll('"', '""');
    return `"${escapedData}"`;
  }
  return data;
};

export const buildCsvLines = (elements:any[], feed:BasicStoreEntityFeed):string[] => {
  const lines: string[] = [];
  const separator = feed.separator ?? ',';
  for (let index = 0; index < elements.length; index += 1) {
    const element = elements[index];
    const dataElements = [];
    for (let attrIndex = 0; attrIndex < feed.feed_attributes.length; attrIndex += 1) {
      const attribute = feed.feed_attributes[attrIndex];
      const mapping = attribute.mappings.find((f) => f.type === element.entity_type);
      if (mapping) {
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

    const line = dataElements.join(separator);
    lines.push(line);
  }
  return lines;
};

const initHttpRollingFeeds = (app: Express.Application) => {
  app.get(`${basePath}/feeds/:id`, async (req: Express.Request, res: Express.Response) => {
    const { id } = req.params;
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
      if (feed.include_header) {
        res.write(`${feed.feed_attributes.map((a) => a.attribute).join(feed.separator)}\r\n`);
      }

      const lines = buildCsvLines(elements, feed);
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
