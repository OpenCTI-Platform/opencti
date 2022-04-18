import { logApp } from '../config/conf';
import { ENTITY_TYPE_IDENTITY_SECTOR } from '../schema/stixDomainObject';
import { elList } from '../database/engine';
import { SYSTEM_USER } from '../utils/access';
import { READ_INDEX_STIX_CORE_RELATIONSHIPS } from '../database/utils';
import { RELATION_LOCATED_AT } from '../schema/stixCoreRelationship';
import { ABSTRACT_STIX_CORE_RELATIONSHIP } from '../schema/general';
import { deleteElementById } from '../database/middleware';

export const up = async (next) => {
  const start = new Date().getTime();
  logApp.info('[MIGRATION] Cleaning located-at relationships between Sectors and Locations');
  const callback = (relations) => relations.map((relation) => deleteElementById(SYSTEM_USER, relation.id, ABSTRACT_STIX_CORE_RELATIONSHIP));
  const filters = [{ key: 'fromType', values: [ENTITY_TYPE_IDENTITY_SECTOR] }];
  const opts = { types: [RELATION_LOCATED_AT], filters, callback };
  await elList(SYSTEM_USER, READ_INDEX_STIX_CORE_RELATIONSHIPS, opts);
  logApp.info(`[MIGRATION] Cleaning located-at relationships between Sectors and Locations done in ${new Date() - start} ms`);
  next();
};

export const down = async (next) => {
  next();
};
