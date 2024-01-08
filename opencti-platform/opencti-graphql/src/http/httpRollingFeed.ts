/* eslint-disable camelcase */
import * as R from 'ramda';
import type Express from 'express';
import nconf from 'nconf';
import { authenticateUserFromRequest, TAXIIAPI } from '../domain/user';
import { basePath } from '../config/conf';
import { ForbiddenAccess } from '../config/errors';
import { BYPASS, executionContext, SYSTEM_USER } from '../utils/access';
import { findById as findFeed } from '../domain/feed';
import type { AuthUser } from '../types/user';
import { listAllThings } from '../database/middleware';
import { minutesAgo } from '../utils/format';
import { isNotEmptyField } from '../database/utils';
import { convertFiltersToQueryOptions } from '../utils/filtering/filtering-resolution';
import { isMultipleAttribute, isObjectAttribute } from '../schema/schema-attributes';

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
const userHaveAccess = (user: AuthUser) => {
  const capabilities = user.capabilities.map((c) => c.name);
  return capabilities.includes(BYPASS) || capabilities.includes(TAXIIAPI);
};

const dataFormat = (separator: string, data: string) => {
  if (data.includes(separator) || data.includes('"')) {
    const escapedData = data.replaceAll('"', '""');
    return `"${escapedData}"`;
  }
  return data;
};

const initHttpRollingFeeds = (app: Express.Application) => {
  app.get(`${basePath}/feeds/:id`, async (req: Express.Request, res: Express.Response) => {
    const { id } = req.params;
    res.set({ 'content-type': 'text/plain; charset=utf-8' });
    try {
      const context = executionContext('rolling_feeds');
      const authUser = await authenticateUserFromRequest(context, req, res);
      const feed = await findFeed(context, SYSTEM_USER, id);
      // The feed doesn't exist at all
      if (!feed) {
        throw ForbiddenAccess();
      }
      // If feed is not public, user must be authenticated
      if (!feed.feed_public && !authUser) {
        throw ForbiddenAccess();
      }
      // If feed is not public, we need to ensure the user access
      if (!feed.feed_public) {
        const userFeed = await findFeed(context, authUser, id);
        if (!userHaveAccess(authUser) || !userFeed) {
          throw ForbiddenAccess();
        }
      }
      // User is available or feed is public
      const user = authUser ?? SYSTEM_USER;
      const filters = feed.filters ? JSON.parse(feed.filters) : undefined;
      const fromDate = minutesAgo(feed.rolling_time);
      const field = feed.feed_date_attribute ?? 'created_at';
      const extraOptions = { defaultTypes: feed.feed_types, field, orderMode: 'desc', after: fromDate };
      const options = await convertFiltersToQueryOptions(context, user, filters, extraOptions);
      const args = { connectionFormat: false, maxSize: SIZE_LIMIT, ...options };
      const paginateElements = await listAllThings(context, user, feed.feed_types, args);
      const elements = R.take(SIZE_LIMIT, paginateElements); // Due to pagination, number of results can be slightly superior
      if (feed.include_header) {
        res.write(`${feed.feed_attributes.map((a) => a.attribute).join(',')}\r\n`);
      }
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
                dataElements.push(dataFormat(feed.separator, data.join(',')));
              } else if (isObjectAttribute(baseKey)) {
                if (isComplexKey) {
                  const [, innerKey] = mapping.attribute.split('.');
                  const dictInnerData = data[innerKey.toUpperCase()];
                  if (isNotEmptyField(dictInnerData)) {
                    dataElements.push(dataFormat(feed.separator, String(dictInnerData)));
                  } else {
                    dataElements.push(dataFormat(feed.separator, ''));
                  }
                } else {
                  dataElements.push(dataFormat(feed.separator, JSON.stringify(data)));
                }
              } else {
                dataElements.push(dataFormat(feed.separator, String(data)));
              }
            } else {
              dataElements.push(dataFormat(feed.separator, ''));
            }
          }
        }
        res.write(dataElements.join(feed.separator ?? ','));
        res.write('\r\n');
      }
      res.send();
    } catch (e) {
      const errorDetail = errorConverter(e);
      res.status(errorDetail.http_status).send(errorDetail);
    }
  });
};

export default initHttpRollingFeeds;
