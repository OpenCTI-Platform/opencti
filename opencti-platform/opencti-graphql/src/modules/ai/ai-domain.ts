/*
Copyright (c) 2021-2024 Filigran SAS

This file is part of the OpenCTI Enterprise Edition ("EE") and is
licensed under the OpenCTI Non-Commercial License (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

https://github.com/OpenCTI-Platform/opencti/blob/master/LICENSE

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
*/

import * as R from 'ramda';
import { listAllToEntitiesThroughRelations, storeLoadById } from '../../database/middleware-loader';
import { ABSTRACT_STIX_CORE_OBJECT, ABSTRACT_STIX_CORE_RELATIONSHIP, ENTITY_TYPE_CONTAINER } from '../../schema/general';
import { RELATION_OBJECT } from '../../schema/stixRefRelationship';
import { extractEntityRepresentativeName, extractRepresentativeDescription } from '../../database/entity-representative';
import type { AuthContext, AuthUser } from '../../types/user';
import type { BasicStoreEntity, BasicStoreRelation } from '../../types/store';
import type { MutationAiContainerGenerateReportArgs } from '../../generated/graphql';
import { isNotEmptyField } from '../../database/utils';
import { FROM_START_STR, UNTIL_END_STR } from '../../utils/format';
import { query } from '../../database/ai-llm';

export const generateContainerReport = async (context: AuthContext, user: AuthUser, args: MutationAiContainerGenerateReportArgs) => {
  const { id, paragraphs = 10, tone = 'technical', format = 'HTML' } = args;
  const container = await storeLoadById(context, user, id, ENTITY_TYPE_CONTAINER) as BasicStoreEntity;
  const elements = await listAllToEntitiesThroughRelations(context, user, id, RELATION_OBJECT, [ABSTRACT_STIX_CORE_OBJECT, ABSTRACT_STIX_CORE_RELATIONSHIP]);
  // generate mappings
  const relationships = elements.filter((n) => n.parent_types.includes(ABSTRACT_STIX_CORE_RELATIONSHIP)) as Array<BasicStoreRelation>;
  const entities = elements.filter((n) => n.parent_types.includes(ABSTRACT_STIX_CORE_OBJECT)) as Array<BasicStoreEntity>;
  const indexedEntities = R.indexBy(R.prop('id'), entities);

  // generate entities involved
  const entitiesInvolved = R.values(indexedEntities).map((n) => {
    return `
      - The ${n.entity_type} ${extractEntityRepresentativeName(n)} (${n.id}) description is: ${extractRepresentativeDescription(n)}.
    `;
  });

  // generate relationships sentences
  const relationshipsSentences = relationships.map((n) => {
    const from = indexedEntities[n.fromId];
    const to = indexedEntities[n.toId];
    if (isNotEmptyField(from) && isNotEmptyField(to)) {
      // eslint-disable-next-line @typescript-eslint/ban-ts-comment
      // @ts-expect-error
      const startTime = n.start_time === FROM_START_STR ? 'unknown date' : n.start_time;
      // eslint-disable-next-line @typescript-eslint/ban-ts-comment
      // @ts-expect-error
      const stopTime = n.stop_time === UNTIL_END_STR ? 'unknown date' : n.stop_time;
      return `
        - The ${from.entity_type} ${extractEntityRepresentativeName(from)} (${from.id}) ${n.relationship_type} the ${to.entity_type} ${extractEntityRepresentativeName(to)} (${to.id}) from ${startTime} to ${stopTime} (${n.description}).
      `;
    }
    return '';
  });

  // build sentences
  const prompt = `
    Generate a cyber threat intelligence report in ${format} format with a title and a content of ${paragraphs} paragraphs of approximately 300 words each without using bullet points. The cyber threat intelligence report 
    should be focused on ${tone} aspects and should be divided into meaningful parts such as: victims, techniques or vulnerabilities used for intrusion, then execution, then persistence and then infrastructure. 
    You should take examples of well-known cyber threat intelligence reports available everywhere. Also, if any indicators of compromise are present in this report, you must generate a table with all of them at the end of the report, including
    file hashes, IP addresses and any relevant technical artifacts.
    
    The report is about ${container.name}. Details are: ${container.description}.
    
    Here are the facts of the report:
    ${relationshipsSentences}
    
    Here are more information that precise elements involved in the above facts:
    ${entitiesInvolved}
  `;

  return query(prompt);
};
