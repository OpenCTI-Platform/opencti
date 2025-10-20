import { v4 as uuidv4 } from 'uuid';
import { stixLoadById } from '../../database/middleware';
import { FilterMode } from '../../generated/graphql';
import { PLAYBOOK_COMPONENTS } from '../../modules/playbook/playbook-components';
import type { BasicStoreEntityPlaybook, ComponentDefinition, NodeDefinition } from '../../modules/playbook/playbook-types';
import type { PirStreamConfiguration } from '../../modules/playbook/playbookComponents/playbook-data-stream-pir-component';
import { ABSTRACT_STIX_CORE_OBJECT } from '../../schema/general';
import { RELATION_IN_PIR } from '../../schema/internalRelationship';
import { isStixRelation } from '../../schema/stixRelationship';
import type { SseEvent, StreamDataEvent } from '../../types/event';
import type { StixBundle } from '../../types/stix-2-1-common';
import type { AuthContext } from '../../types/user';
import { SYSTEM_USER } from '../../utils/access';
import { isStixMatchFilterGroup } from '../../utils/filtering/filtering-stix/stix-filtering';
import { isValidEventType } from './playbookManagerUtils';
import { STIX_SPEC_VERSION } from '../../database/stix';
import { playbookExecutor } from './playbookExecutor';

export const isEventMatchesPir = async (context: AuthContext, pirList: { value: string }[], eventData: unknown) => {
  const filtersOnInPirRel = pirList ? {
    filterGroups: [],
    mode: FilterMode.And,
    filters: [{
      key: ['toId'],
      values: pirList.map((n) => n.value),
    }],
  } : null;

  return !filtersOnInPirRel || await isStixMatchFilterGroup(context, SYSTEM_USER, eventData, filtersOnInPirRel);
};

export const listenPirEvents = async (
  context: AuthContext,
  streamEvent : SseEvent<StreamDataEvent>,
  instance: NodeDefinition,
  playbook:BasicStoreEntityPlaybook
) => {
  const { id: eventId, data: { data, type, scope } } = streamEvent;
  const def = JSON.parse(playbook.playbook_definition) as ComponentDefinition;

  if (scope === 'internal' && isStixRelation(data) && data.relationship_type === RELATION_IN_PIR) {
    const connector = PLAYBOOK_COMPONENTS[instance.component_id];
    const configuration = JSON.parse(instance.configuration ?? '{}') as PirStreamConfiguration;

    const {
      filters: sourceFilters,
      inPirFilters
    } = configuration;

    const isMatchPir = await isEventMatchesPir(
      context,
      inPirFilters,
      data
    );

    const filtersOnSource = sourceFilters ? JSON.parse(sourceFilters) : null;

    const isValidEvent = isValidEventType(type, configuration);

    // 02. Execute the component
    if (isValidEvent && isMatchPir) {
      const entity = await stixLoadById(context, SYSTEM_USER, data.source_ref, ABSTRACT_STIX_CORE_OBJECT);
      const isEntityMatch = entity && await isStixMatchFilterGroup(context, SYSTEM_USER, entity, filtersOnSource);
      if (isEntityMatch) {
        const nextStep = { component: connector, instance };
        const bundle: StixBundle = {
          id: uuidv4(),
          spec_version: STIX_SPEC_VERSION,
          type: 'bundle',
          objects: [entity]
        };
        await playbookExecutor({
          eventId,
          // Basic
          executionId: uuidv4(),
          playbookId: playbook.id,
          dataInstanceId: data.id,
          definition: def,
          // Steps
          previousStep: null,
          nextStep,
          // Data
          previousStepBundle: null,
          bundle,
        });
      }
    }
  }
};
