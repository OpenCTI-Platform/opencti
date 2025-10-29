import { v4 as uuidv4 } from 'uuid';
import { stixLoadById } from '../../database/middleware';
import { FilterMode } from '../../generated/graphql';
import { PLAYBOOK_COMPONENTS } from '../../modules/playbook/playbook-components';
import type { BasicStoreEntityPlaybook, ComponentDefinition, NodeDefinition } from '../../modules/playbook/playbook-types';
import type { PirStreamConfiguration } from '../../modules/playbook/components/data-stream-pir-component';
import { ABSTRACT_STIX_CORE_OBJECT } from '../../schema/general';
import { isStixRelation } from '../../schema/stixRelationship';
import type { SseEvent, StreamDataEvent, StreamDataEventType } from '../../types/event';
import type { StixBundle, StixCoreObject, StixObject } from '../../types/stix-2-1-common';
import type { AuthContext } from '../../types/user';
import { SYSTEM_USER } from '../../utils/access';
import { isStixMatchFilterGroup } from '../../utils/filtering/filtering-stix/stix-filtering';
import { isValidEventType, StreamDataEventTypeEnum } from './playbookManagerUtils';
import { STIX_SPEC_VERSION } from '../../database/stix';
import { playbookExecutor } from './playbookExecutor';
import { storeLoadById } from '../../database/middleware-loader';
import { RELATION_IN_PIR } from '../../schema/internalRelationship';

export const buildPirFilters = (pirList?: { value: string }[]) => {
  return pirList ? {
    filterGroups: [],
    mode: FilterMode.And,
    filters: [{
      key: ['toId'],
      values: pirList.map((n) => n.value),
    }],
  } : null;
};

export const listOfPirInEntity = async (entityId:string, context: AuthContext):Promise<any[]> => {
  let list:any[] = [];
  const entityFromId = await storeLoadById(context, SYSTEM_USER, entityId, ABSTRACT_STIX_CORE_OBJECT);
  if (entityFromId && 'pir_information' in entityFromId && Array.isArray(entityFromId.pir_information)) {
    list = entityFromId.pir_information;
  }
  return list;
};

export const isEventInPir = async (streamEvent : StreamDataEvent, context?: AuthContext) => {
  const { data, scope } = streamEvent;
  if (scope === 'internal') { return isStixRelation(data) && data.relationship_type === RELATION_IN_PIR; }
  if (scope === 'external' && context) {
    const entityPirList = await listOfPirInEntity(data.id, context);
    return entityPirList.length > 0;
  }
  return false;
};

export const isEventMatchesPir = async (context: AuthContext, eventData: StixCoreObject | StreamDataEvent, pirList?: { value: string }[], eventType?: StreamDataEventType) => {
  if (eventType === StreamDataEventTypeEnum.UPDATE && pirList && 'id' in eventData) {
    const entityPirList = await listOfPirInEntity(eventData.id, context);
    if (entityPirList.length > 0) {
      return entityPirList.some((pirId) => pirList.some((selectedPir) => pirId.pir_id === selectedPir.value));
    }
  }
  const filtersOnInPirRel = buildPirFilters(pirList);
  return !filtersOnInPirRel || await isStixMatchFilterGroup(context, SYSTEM_USER, eventData, filtersOnInPirRel);
};

export const listenPirEvents = async (
  context: AuthContext,
  streamEvent : SseEvent<StreamDataEvent>,
  instance: NodeDefinition,
  playbook:BasicStoreEntityPlaybook
) => {
  const { id: eventId, data: { data, type } } = streamEvent;
  const def = JSON.parse(playbook.playbook_definition) as ComponentDefinition;
  const connector = PLAYBOOK_COMPONENTS[instance.component_id];
  const configuration = JSON.parse(instance.configuration ?? '{}') as PirStreamConfiguration;
  const isValidEvent = isValidEventType(type, configuration);

  const {
    filters: sourceFilters,
    inPirFilters
  } = configuration;

  const filtersOnSource = sourceFilters ? JSON.parse(sourceFilters) : null;

  const eventInPir = await isEventInPir(streamEvent.data, context);

  if (isValidEvent && eventInPir) {
    const isMatchPir = await isEventMatchesPir(context, data, inPirFilters, type);

    // 02. Execute the component
    if (isMatchPir) {
      let isEntityMatchFilters: boolean | undefined = false;
      let entity:StixObject | undefined;

      if (isStixRelation(data) && (type === StreamDataEventTypeEnum.CREATE || type === StreamDataEventTypeEnum.DELETE)) {
        entity = await stixLoadById(context, SYSTEM_USER, data.source_ref, ABSTRACT_STIX_CORE_OBJECT);
        isEntityMatchFilters = entity && await isStixMatchFilterGroup(context, SYSTEM_USER, entity, filtersOnSource);
      } else if (type === StreamDataEventTypeEnum.UPDATE) {
        entity = data;
        isEntityMatchFilters = await isStixMatchFilterGroup(context, SYSTEM_USER, data, filtersOnSource);
      }
      if (isEntityMatchFilters && entity) {
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
          dataInstanceId: entity.id,
          definition: def,
          // Steps
          previousStep: null,
          nextStep,
          // Data
          previousStepBundle: null,
          bundle,
          event: streamEvent.data
        });
      }
    }
  }
};
