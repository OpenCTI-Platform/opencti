// region [>=6.5 & <6.8]
import { listAllToEntitiesThroughRelations, storeLoadById } from '../../../database/middleware-loader';
import { ABSTRACT_STIX_DOMAIN_OBJECT, ENTITY_TYPE_CONTAINER, ENTITY_TYPE_IDENTITY } from '../../../schema/general';
import { RELATION_CREATED_BY, RELATION_OBJECT, RELATION_OBJECT_LABEL } from '../../../schema/stixRefRelationship';
import {
  ENTITY_TYPE_ATTACK_PATTERN,
  ENTITY_TYPE_CAMPAIGN,
  ENTITY_TYPE_INCIDENT,
  ENTITY_TYPE_INTRUSION_SET,
  ENTITY_TYPE_THREAT_ACTOR_GROUP
} from '../../../schema/stixDomainObject';
import { checkEnterpriseEdition } from '../../../utils/ee';
import { ENTITY_TYPE_LABEL } from '../../../schema/stixMetaObject';
import { RELATION_TARGETS, RELATION_USES } from '../../../schema/stixCoreRelationship';
import { ENTITY_TYPE_THREAT_ACTOR_INDIVIDUAL } from '../../threatActorIndividual/threatActorIndividual-types';
import { getDraftContext } from '../../../utils/draftContext';
import { UnsupportedError } from '../../../config/errors';
import { generateOpenBasScenarioWithInjectPlaceholders } from '../xtm-domain';

/** @deprecated [>=6.5 & <6.8]. Use `generateOpenBasScenarioWithInjectPlaceholders */
export const generateOpenBasScenario = async (context, user, stixCoreObject, attackPatterns, labels, author, simulationType, interval, selection) => {
  const response = await generateOpenBasScenarioWithInjectPlaceholders(context, user, stixCoreObject, attackPatterns, labels, author, { interval, selection, simulationType });
  return response.urlResponse;
};

/** @deprecated [>=6.5 & <6.8]. Use `generateContainerScenarioWithInjectPlaceholders */
export const generateContainerScenario = async (context, user, args) => {
  if (getDraftContext(context, user)) {
    throw UnsupportedError('Cannot generate scenario in draft');
  }
  const { id, interval, selection, simulationType = 'technical', useAI = false } = args;
  if (useAI || simulationType !== 'technical') {
    await checkEnterpriseEdition(context);
  }
  const container = await storeLoadById(context, user, id, ENTITY_TYPE_CONTAINER);
  const author = await listAllToEntitiesThroughRelations(context, user, id, RELATION_CREATED_BY, [ENTITY_TYPE_IDENTITY]);
  const labels = await listAllToEntitiesThroughRelations(context, user, id, RELATION_OBJECT_LABEL, [ENTITY_TYPE_LABEL]);
  const attackPatterns = await listAllToEntitiesThroughRelations(context, user, id, RELATION_OBJECT, [ENTITY_TYPE_ATTACK_PATTERN]);
  return generateOpenBasScenario(context, user, container, attackPatterns, labels, (author && author.length > 0 ? author.at(0) : 'Unknown'), simulationType, interval, selection);
};

/** @deprecated [>=6.5 & <6.8]. Use `generateThreatScenarioWithInjectPlaceholders */
export const generateThreatScenario = async (context, user, args) => {
  if (getDraftContext(context, user)) {
    throw UnsupportedError('Cannot generate scenario in draft');
  }
  const { id, interval, selection, simulationType = 'technical', useAI = false } = args;
  if (useAI || simulationType !== 'technical') {
    await checkEnterpriseEdition(context);
  }
  const stixCoreObject = await storeLoadById(context, user, id, ABSTRACT_STIX_DOMAIN_OBJECT);
  const labels = await listAllToEntitiesThroughRelations(context, user, id, RELATION_OBJECT_LABEL, [ENTITY_TYPE_LABEL]);
  const author = await listAllToEntitiesThroughRelations(context, user, id, RELATION_CREATED_BY, [ENTITY_TYPE_IDENTITY]);
  const attackPatterns = await listAllToEntitiesThroughRelations(context, user, id, RELATION_USES, [ENTITY_TYPE_ATTACK_PATTERN]);
  return generateOpenBasScenario(context, user, stixCoreObject, attackPatterns, labels, (author && author.length > 0 ? author.at(0) : 'Unknown'), simulationType, interval, selection);
};

/** @deprecated [>=6.5 & <6.8]. Use `generateVictimScenarioWithInjectPlaceholders */
export const generateVictimScenario = async (context, user, args) => {
  if (getDraftContext(context, user)) {
    throw UnsupportedError('Cannot generate scenario in draft');
  }
  const { id, interval, selection, simulationType = 'technical', useAI = false } = args;
  if (useAI || simulationType !== 'technical') {
    await checkEnterpriseEdition(context);
  }
  const stixCoreObject = await storeLoadById(context, user, id, ABSTRACT_STIX_DOMAIN_OBJECT);
  const labels = await listAllToEntitiesThroughRelations(context, user, id, RELATION_OBJECT_LABEL, [ENTITY_TYPE_LABEL]);
  const author = await listAllToEntitiesThroughRelations(context, user, id, RELATION_CREATED_BY, [ENTITY_TYPE_IDENTITY]);
  const threats = await listAllToEntitiesThroughRelations(
    context,
    user,
    id,
    RELATION_TARGETS,
    [
      ENTITY_TYPE_THREAT_ACTOR_GROUP,
      ENTITY_TYPE_THREAT_ACTOR_INDIVIDUAL,
      ENTITY_TYPE_INTRUSION_SET,
      ENTITY_TYPE_CAMPAIGN,
      ENTITY_TYPE_INCIDENT
    ]
  );
  const threatsIds = threats.map((n) => n.id);
  const attackPatterns = await listAllToEntitiesThroughRelations(context, user, threatsIds, RELATION_USES, [ENTITY_TYPE_ATTACK_PATTERN]);
  return generateOpenBasScenario(context, user, stixCoreObject, attackPatterns, labels, (author && author.length > 0 ? author.at(0) : 'Unknown'), simulationType, interval, selection);
};
// endregion
