import { useRef } from 'react';
import { GraphQLTaggedNode } from 'react-relay';
import { commitMutation } from '../../../../relay/environment';
import {
  contentMappingAskAnalysisMutation,
  contentMappingDeleteMutation,
  contentMappingDomainObjectAddMutation,
  contentMappingFieldPatchMutation,
  contentMappingObservableAddMutation,
  contentMappingRelationDeleteMutation,
  contentMappingRelationsAddMutation,
} from './contentMappingQueries';
import { ContentMappingReviewState, encodeMapping, encodeReview, familyOf, MappableEntity, mappingKey } from './contentMappingModel';
import { creationInputFor } from './mappingValue';

// Observable types the one-click mapping can create, with their creation input key.
const OBSERVABLE_INPUT_KEYS: Record<string, string> = {
  'IPv4-Addr': 'IPv4Addr',
  'IPv6-Addr': 'IPv6Addr',
  'Domain-Name': 'DomainName',
  Url: 'Url',
  'Email-Addr': 'EmailAddr',
  StixFile: 'StixFile',
  'Mac-Addr': 'MacAddr',
  'Autonomous-System': 'AutonomousSystem',
};

// Domain objects are created by name; observables only for the types above.
export const canCreateType = (type: string) => !!OBSERVABLE_INPUT_KEYS[type] || familyOf(type) !== 'observables';

export interface EnrichmentValues {
  objectMarking?: string[];
  objectLabel?: string[];
  confidence?: number;
}

const commit = <T>(mutation: GraphQLTaggedNode, variables: Record<string, unknown>) => new Promise<T>((resolve, reject) => {
  commitMutation({
    mutation,
    variables,
    onCompleted: (response: unknown) => resolve(response as T),
    onError: (error: Error) => reject(error),
  });
});

interface Container {
  id: string;
  objectIds: ReadonlySet<string>;
  mapping: Record<string, string>;
  review: ContentMappingReviewState;
  // Raw content_mapping + content_mapping_review: tells when the server state changed.
  serverVersion: string;
  createdById?: string | null;
}

// Every action re-reads the latest state from a ref, so that two quick actions do not overwrite each
// other's mapping (content_mapping is replaced as a whole on each patch).
const useContentMappingActions = (container: Container, refresh: () => void) => {
  const state = useRef({ mapping: container.mapping, review: container.review, objectIds: new Set(container.objectIds) });
  const serverVersion = useRef(container.serverVersion);
  if (serverVersion.current !== container.serverVersion) {
    serverVersion.current = container.serverVersion;
    state.current = { mapping: container.mapping, review: container.review, objectIds: new Set(container.objectIds) };
  }

  const patchMappingAndReview = async (mapping: Record<string, string>, review: ContentMappingReviewState) => {
    state.current = { ...state.current, mapping, review };
    await commit(contentMappingFieldPatchMutation, {
      id: container.id,
      input: [
        { key: 'content_mapping', value: [encodeMapping(mapping)] },
        { key: 'content_mapping_review', value: [encodeReview(review)] },
      ],
    });
  };

  const withoutIgnored = (review: ContentMappingReviewState, keys: string[]) => ({
    ...review,
    ignored: Object.fromEntries(Object.entries(review.ignored).filter(([key]) => !keys.includes(key))),
  });

  // Maps values to existing objects, adding the objects to the container when needed.
  const mapEntities = async (entries: { value: string; entity: MappableEntity }[], source: string) => {
    const toAdd = [...new Set(entries.map((e) => e.entity.id).filter((id) => !state.current.objectIds.has(id)))];
    if (toAdd.length > 0) {
      await commit(contentMappingRelationsAddMutation, { id: container.id, toIds: toAdd });
      toAdd.forEach((id) => state.current.objectIds.add(id));
    }
    const keys = entries.map((e) => mappingKey(e.value));
    const mapping = { ...state.current.mapping };
    const sources = { ...state.current.review.sources };
    entries.forEach(({ value, entity }) => {
      mapping[mappingKey(value)] = entity.standard_id;
      sources[mappingKey(value)] = source;
    });
    await patchMappingAndReview(mapping, { ...withoutIgnored(state.current.review, keys), sources });
    return { addedToContainer: toAdd };
  };

  const createEntity = async (type: string, value: string, enrichment: EnrichmentValues = {}): Promise<MappableEntity> => {
    const input = creationInputFor(type, value);
    const common = { objectMarking: enrichment.objectMarking, objectLabel: enrichment.objectLabel, createdBy: container.createdById ?? undefined };
    const observableKey = OBSERVABLE_INPUT_KEYS[type];
    if (observableKey) {
      const response = await commit<{ stixCyberObservableAdd: MappableEntity }>(contentMappingObservableAddMutation, { type, ...common, [observableKey]: input });
      return response.stixCyberObservableAdd;
    }
    const response = await commit<{ stixDomainObjectAdd: MappableEntity }>(contentMappingDomainObjectAddMutation, {
      input: { type, ...common, ...input, confidence: enrichment.confidence },
    });
    return response.stixDomainObjectAdd;
  };

  // Undoes a one-click mapping: the value is unmapped, the object leaves the container if this
  // mapping added it, and it is deleted if this mapping created it.
  const undoMapping = async (value: string, entity: MappableEntity, { created, addedToContainer }: { created: boolean; addedToContainer: boolean }) => {
    const key = mappingKey(value);
    const { [key]: _, ...mapping } = state.current.mapping;
    await patchMappingAndReview(mapping, state.current.review);
    if (created) {
      await commit(contentMappingDeleteMutation, { id: entity.id });
    } else if (addedToContainer) {
      await commit(contentMappingRelationDeleteMutation, { id: container.id, toId: entity.id });
    }
    refresh();
  };

  const mapExisting = async (value: string, entity: MappableEntity, source: string) => {
    const { addedToContainer } = await mapEntities([{ value, entity }], source);
    refresh();
    return () => undoMapping(value, entity, { created: false, addedToContainer: addedToContainer.length > 0 });
  };

  const createAndMap = async (value: string, type: string, source: string) => {
    const entity = await createEntity(type, value);
    await mapEntities([{ value, entity }], source);
    refresh();
    return { entity, undo: () => undoMapping(value, entity, { created: true, addedToContainer: true }) };
  };

  // Validates suggestions: existing objects are mapped, the others are created first, with the
  // enrichment of the bulk bar. AI suggestions are only ever validated through this explicit action.
  const validate = async (items: { value: string; entity: MappableEntity | null; entityType: string; source: string }[], enrichment: EnrichmentValues = {}) => {
    const entries: { value: string; entity: MappableEntity; source: string }[] = [];
    for (const item of items) {
      entries.push({ value: item.value, source: item.source, entity: item.entity ?? await createEntity(item.entityType, item.value, enrichment) });
    }
    const bySource = new Map<string, typeof entries>();
    entries.forEach((entry) => bySource.set(entry.source, [...(bySource.get(entry.source) ?? []), entry]));
    for (const [source, sourceEntries] of bySource) {
      await mapEntities(sourceEntries, source);
    }
    refresh();
    return entries.length;
  };

  const ignore = async (items: { key: string; value: string; entityType: string; standardId: string | null }[]) => {
    const ignored = { ...state.current.review.ignored };
    items.forEach(({ key, value, entityType, standardId }) => {
      ignored[key] = { value, entityType, ...(standardId ? { standardId } : {}) };
    });
    await patchMappingAndReview(state.current.mapping, { ...state.current.review, ignored });
    refresh();
  };

  const restore = async (keys: string[]) => {
    await patchMappingAndReview(state.current.mapping, withoutIgnored(state.current.review, keys));
    refresh();
  };

  const unmap = async (keys: string[]) => {
    const mapping = Object.fromEntries(Object.entries(state.current.mapping).filter(([key]) => !keys.includes(mappingKey(key))));
    await patchMappingAndReview(mapping, state.current.review);
    refresh();
  };

  const changeType = async (key: string, entityType: string) => {
    await patchMappingAndReview(state.current.mapping, { ...state.current.review, types: { ...state.current.review.types, [key]: entityType } });
    refresh();
  };

  const askAnalysis = async (contentSource: string, contentType: 'fields' | 'file') => {
    await commit(contentMappingAskAnalysisMutation, { id: container.id, contentSource, contentType });
  };

  return { mapExisting, createAndMap, validate, ignore, restore, unmap, changeType, askAnalysis };
};

export default useContentMappingActions;
