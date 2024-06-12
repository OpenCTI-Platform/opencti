import { uniq } from 'ramda';
import { logApp } from '../config/conf';
import { executionContext, SYSTEM_USER } from '../utils/access';
import { getSettings } from '../domain/settings';
import { listAllEntities } from '../database/middleware-loader';
import { ENTITY_TYPE_GROUP } from '../schema/internalObject';
import { ENTITY_TYPE_MARKING_DEFINITION } from '../schema/stixMetaObject';
import { groupAllowedMarkings, groupEditField } from '../domain/group';
import { elUpdateByQueryForMigration } from '../database/engine';
import { READ_INDEX_INTERNAL_OBJECTS } from '../database/utils';

const message = '[MIGRATION] Remove max shareable markings from platform settings and add them in groups';

export const up = async (next) => {
  logApp.info(`${message} > started`);
  const context = executionContext('migration', SYSTEM_USER);
  const groups = await listAllEntities(context, context.user, [ENTITY_TYPE_GROUP], { connectionFormat: false });
  const markings = await listAllEntities(context, context.user, [ENTITY_TYPE_MARKING_DEFINITION], {});
  const markingTypes = uniq(markings.map((m) => m.definition_type));
  const settings = await getSettings(context);
  const platformMaxShareableMarkingIds = settings.platform_data_sharing_max_markings || [];
  const platformMaxShareableMarkings = markings.filter((m) => platformMaxShareableMarkingIds.includes(m.id));

  const groupMaxMarkingRelationCreationsPromises = [];
  for (let i = 0; i < groups.length; i += 1) {
    const group = groups[i];
    // construct the new group max shareable markings (a marking for each existing marking definition type, undefined if type not shareable)
    const allowedMarkings = await groupAllowedMarkings(context, context.user, group.id);
    markingTypes.forEach((type) => { // for each existing marking definition type
      const sortedAllowedMarkingsOfType = allowedMarkings.filter((m) => m.definition_type === type)
        .sort((a, b) => b.x_opencti_order - a.x_opencti_order);
      const sortedMaxMarkingsOfType = platformMaxShareableMarkings.filter((m) => m.definition_type === type)
        .sort((a, b) => b.x_opencti_order - a.x_opencti_order);
      // case 1: a platform max marking has been defined for this type
      if (sortedMaxMarkingsOfType.length > 0) {
        const platformMaxMarkingForType = sortedMaxMarkingsOfType[0];
        const platformMaxMarkingIdForType = platformMaxMarkingForType.id;
        // case 1.1: if it is allowed, keep the platform max marking of this type
        if (allowedMarkings.map((m) => m.id).includes(platformMaxMarkingIdForType)) {
          const value = [{ type, value: platformMaxMarkingIdForType }];
          groupMaxMarkingRelationCreationsPromises.push(groupEditField(context, context.user, group.id, { key: 'max_shareable_markings', value }));
        }
        // case 1.2: if not allowed
        // - keep the most restrictive allowed marking that has an order inferior to the platform max marking if it exists
        // - not shareable if it doesnt exist
        const sortedShareableMarkings = sortedAllowedMarkingsOfType.filter((m) => m.x_opencti_order <= platformMaxMarkingForType.x_opencti_order);
        const markingId = sortedShareableMarkings.length > 0 ? sortedShareableMarkings[0].id : 'none';
        const value = [{ type, value: markingId }];
        groupMaxMarkingRelationCreationsPromises.push(groupEditField(context, context.user, group.id, { key: 'max_shareable_markings', value }));
      }
      // case 2 : no marking defined for this type -> all the markings of this type should be shareable, so nothing to do
    });
  }

  await Promise.all(groupMaxMarkingRelationCreationsPromises);

  // remove platform_data_sharing_max_markings from settings
  const updateQuery = {
    script: {
      params: { null: null },
      source: 'ctx._source.platform_data_sharing_max_markings = params.null',
    },
    query: {
      bool: {
        must: [
          { term: { 'entity_type.keyword': { value: 'Settings' } } },
        ],
      },
    },
  };
  await elUpdateByQueryForMigration(
    message,
    [READ_INDEX_INTERNAL_OBJECTS],
    updateQuery
  );

  // do your migration
  logApp.info(`${message} > done`);
  next();
};

export const down = async (next) => {
  next();
};
