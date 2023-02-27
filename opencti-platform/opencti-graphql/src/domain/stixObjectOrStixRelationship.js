import { elLoadById } from '../database/engine';
import { READ_PLATFORM_INDICES } from '../database/utils';
import { storeLoadById } from '../database/middleware-loader';
import { ABSTRACT_STIX_META_RELATIONSHIP } from '../schema/general';
import { FunctionalError, ValidationError } from '../config/errors';
import { isStixMetaRelationship } from '../schema/stixMetaRelationship';
import { deleteRelationsByFromAndTo } from '../database/middleware';
import { notify } from '../database/redis';
import { BUS_TOPICS } from '../config/conf';
import { getAttributesConfiguration, getEntitySettingFromCache } from '../modules/entitySetting/entitySetting-utils';
import { schemaRelationsRefDefinition } from '../schema/schema-relationsRef';

// eslint-disable-next-line import/prefer-default-export
export const findById = async (context, user, id) => {
  return elLoadById(context, user, id, null, READ_PLATFORM_INDICES);
};

export const stixObjectOrRelationshipDeleteRelation = async (context, user, stixObjectOrRelationshipId, toId, relationshipType, type) => {
  const stixObjectOrRelationship = await storeLoadById(context, user, stixObjectOrRelationshipId, type);
  if (!stixObjectOrRelationship) {
    throw FunctionalError('Cannot delete the relation, Stix-Object or Stix-Relationship cannot be found.');
  }
  if (!isStixMetaRelationship(relationshipType)) {
    throw FunctionalError(`Only ${ABSTRACT_STIX_META_RELATIONSHIP} can be deleted through this method.`);
  }

  // check mandatory attribute
  const entitySetting = await getEntitySettingFromCache(context, stixObjectOrRelationship.entity_type);
  const attributesConfiguration = getAttributesConfiguration(entitySetting);
  if (attributesConfiguration) {
    const attribute = attributesConfiguration.find((attr) => attr.name === schemaRelationsRefDefinition.convertDatabaseNameToInputName(relationshipType));
    if (attribute?.mandatory && stixObjectOrRelationship[relationshipType].length === 1) {
      throw ValidationError(attribute.name, { message: 'This attribute is mandatory', attribute: attribute.name });
    }
  }

  await deleteRelationsByFromAndTo(context, user, stixObjectOrRelationshipId, toId, relationshipType, ABSTRACT_STIX_META_RELATIONSHIP);
  return notify(BUS_TOPICS[type].EDIT_TOPIC, stixObjectOrRelationship, user);
};
