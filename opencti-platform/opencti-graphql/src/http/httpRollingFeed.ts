/* eslint-disable camelcase */
import * as R from 'ramda';
import type Express from 'express';
import { authenticateUserFromRequest, TAXIIAPI } from '../domain/user';
import { basePath } from '../config/conf';
import { AuthRequired, ForbiddenAccess } from '../config/errors';
import { BYPASS, executionContext } from '../utils/access';
import { findById as findFeed } from '../domain/feed';
import type { AuthContext, AuthUser } from '../types/user';
import { listThings } from '../database/middleware';
import { minutesAgo } from '../utils/format';
import { isNotEmptyField } from '../database/utils';
import { convertFiltersToQueryOptions } from '../utils/filtering';
import { isDictionaryAttribute, isMultipleAttribute } from '../schema/fieldDataAdapter';

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
const extractUserFromRequest = async (context: AuthContext, req: Express.Request, res: Express.Response) => {
  const user = await authenticateUserFromRequest(context, req, res);
  if (!user) {
    res.setHeader('WWW-Authenticate', 'Basic, Bearer');
    throw AuthRequired();
  }
  if (!userHaveAccess(user)) throw ForbiddenAccess();
  return user;
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
    try {
      const context = executionContext('rolling_feeds');
      const user = await extractUserFromRequest(context, req, res);
      const feed = await findFeed(context, user, id);
      const filters = feed.filters ? JSON.parse(feed.filters) : undefined;
      const fromDate = minutesAgo(feed.rolling_time);
      const extraOptions = { defaultTypes: feed.feed_types, field: 'created_at', orderMode: 'desc', after: fromDate };
      const options = await convertFiltersToQueryOptions(context, filters, extraOptions);
      const args = { connectionFormat: false, first: 5000, ...options };
      const elements = await listThings(context, user, feed.feed_types, args);
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
              if (isMultipleAttribute(baseKey)) {
                dataElements.push(dataFormat(feed.separator, data.join(',')));
              } else if (isDictionaryAttribute(baseKey)) {
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
