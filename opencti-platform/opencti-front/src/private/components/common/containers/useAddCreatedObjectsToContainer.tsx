import React, { ReactNode, useEffect, useRef, useState } from 'react';
import { Form, Formik, FormikConfig } from 'formik';
import { graphql } from 'react-relay';
import { fetchQuery, MESSAGING$ } from '../../../../relay/environment';
import { useFormatter } from '../../../../components/i18n';
import CommitMessage from '../form/CommitMessage';
import { ExternalReferencesValues } from '../form/ExternalReferencesField';
import { addObjectToContainer, CreatedObject, removeObjectFromContainer } from './containerObjects';
import { useAddCreatedObjectsToContainerIndicatorsQuery$data } from './__generated__/useAddCreatedObjectsToContainerIndicatorsQuery.graphql';

/** The objects created within this delay of each other are added together, with a single message. */
export const CREATED_OBJECTS_BATCH_DELAY_MS = 1000;

const indicatorsBasedOnQuery = graphql`
  query useAddCreatedObjectsToContainerIndicatorsQuery($filters: FilterGroup) {
    indicators(first: 50, filters: $filters) {
      edges {
        node {
          id
          standard_id
          entity_type
          parent_types
          representative {
            main
          }
        }
      }
    }
  }
`;

interface UseAddCreatedObjectsToContainerArgs {
  containerId: string;
  // Entity type of the container, e.g. 'Report'
  containerType?: string;
  knowledgeGraph?: boolean;
  paginationOptions?: Record<string, unknown>;
  enableReferences?: boolean;
  // True in content mapping, where nothing is added automatically
  disabled?: boolean;
  isInContainer: (id: string) => boolean;
  // Called for each object added, to tick it in the panel and update the parent view (e.g. the graph)
  onAdded: (object: CreatedObject) => void;
  // Called for each object removed by Undo
  onRemoved: (object: CreatedObject) => void;
  // The full object for the parent view (e.g. a graph node), when the creation response is not enough
  resolveObject?: (id: string) => Promise<CreatedObject>;
}

interface CreatedObjectsBatchItem {
  object: CreatedObject;
  withIndicator: boolean;
}

interface References {
  commitMessage: string;
  references: string[];
}

interface ReferencesFormValues {
  message: string;
  references: ExternalReferencesValues;
}

const isObservable = (object: CreatedObject) => (object.parent_types ?? []).includes('Stix-Cyber-Observable');

const fetchIndicatorsBasedOn = async (observableId: string): Promise<CreatedObject[]> => {
  const filters = {
    mode: 'and',
    filterGroups: [],
    filters: [{
      key: 'regardingOf',
      operator: 'eq',
      mode: 'or',
      values: [
        { key: 'id', values: [observableId] },
        { key: 'relationship_type', values: ['based-on'] },
      ],
    }],
  };
  const data = await fetchQuery(indicatorsBasedOnQuery, { filters }).toPromise() as useAddCreatedObjectsToContainerIndicatorsQuery$data;
  return (data?.indicators?.edges ?? []).flatMap((edge) => (edge?.node ? [edge.node] : []));
};

/**
 * Adds the objects created from a container's add panel to the container, and confirms it with a message offering Undo.
 * Render `referencesDialog` outside the panel's drawer: Undo keeps working once the drawer is closed.
 */
export const useAddCreatedObjectsToContainer = (args: UseAddCreatedObjectsToContainerArgs) => {
  const { t_i18n } = useFormatter();
  // The latest arguments: the batch is flushed after a delay, and Undo is clicked later
  const argsRef = useRef(args);
  argsRef.current = args;
  const mountedRef = useRef(true);
  const batchRef = useRef<CreatedObjectsBatchItem[]>([]);
  const timerRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const referencesResolverRef = useRef<((references: References | null) => void) | null>(null);
  const [referencesDialogOpen, setReferencesDialogOpen] = useState(false);

  useEffect(() => {
    mountedRef.current = true;
    return () => {
      mountedRef.current = false;
    };
  }, []);

  const containerLabel = () => {
    const { containerType } = argsRef.current;
    return containerType ? t_i18n(`entity_${containerType}`) : t_i18n('container');
  };

  const askReferences = () => new Promise<References | null>((resolve) => {
    referencesResolverRef.current = resolve;
    setReferencesDialogOpen(true);
  });
  const resolveReferences = (references: References | null) => {
    const resolve = referencesResolverRef.current;
    referencesResolverRef.current = null;
    setReferencesDialogOpen(false);
    resolve?.(references);
  };

  const addedMessage = (added: CreatedObject[]) => {
    const values = { containerType: containerLabel(), count: added.length };
    if (added.length === 1) {
      return t_i18n('{entityType} created and added to the {containerType}', {
        values: { ...values, entityType: t_i18n(`entity_${added[0].entity_type}`) },
      });
    }
    if (added.every(isObservable)) return t_i18n('{count} observables added to the {containerType}', { values });
    if (!added.some(isObservable)) return t_i18n('{count} entities added to the {containerType}', { values });
    return t_i18n('{count} objects added to the {containerType}', { values });
  };

  const undo = async (added: CreatedObject[]) => {
    const { containerId, knowledgeGraph, paginationOptions, enableReferences } = argsRef.current;
    let references: References = { commitMessage: '', references: [] };
    if (enableReferences) {
      // The references dialog belongs to the panel: without it, the objects are removed by unticking them
      if (!mountedRef.current) {
        MESSAGING$.notifyWarning(t_i18n('Untick the objects in the add panel to remove them'));
        return;
      }
      const given = await askReferences();
      if (!given) return;
      references = given;
    }
    const results = await Promise.allSettled(added.map((object) => removeObjectFromContainer({
      containerId,
      objectId: object.id,
      knowledgeGraph,
      paginationOptions,
      ...references,
    })));
    results.forEach((result, index) => {
      if (result.status === 'fulfilled') argsRef.current.onRemoved(added[index]);
    });
    // A failed removal is already reported by the mutation
    if (results.every((result) => result.status === 'fulfilled')) {
      MESSAGING$.notifySuccess(t_i18n('Removed from the {containerType}', { values: { containerType: containerLabel() } }));
    }
  };

  const flush = async () => {
    const batch = batchRef.current;
    batchRef.current = [];
    const { containerId, knowledgeGraph, paginationOptions, enableReferences, isInContainer, resolveObject } = argsRef.current;
    // The indicators created with an observable ("Create indicator") are added too
    const indicators = await Promise.all(batch
      .filter((item) => item.withIndicator)
      .map((item) => fetchIndicatorsBasedOn(item.object.id).catch(() => [])));
    const created = [...batch.map((item) => item.object), ...indicators.flat()]
      .filter((object, index, all) => all.findIndex((o) => o.id === object.id) === index);
    // An existing object returned by the creation (upsert) may already be in the container: it is neither added nor undone
    const toAdd = created.filter((object) => !isInContainer(object.id));
    if (toAdd.length === 0) {
      if (created.length > 0) {
        MESSAGING$.notifySuccess(t_i18n('Already in the {containerType}', { values: { containerType: containerLabel() } }));
      }
      return;
    }
    let references: References = { commitMessage: '', references: [] };
    if (enableReferences) {
      const given = await askReferences();
      if (!given) {
        MESSAGING$.notifyWarning(t_i18n('Objects created but not added to the {containerType}', { values: { containerType: containerLabel() } }));
        return;
      }
      references = given;
    }
    const results = await Promise.allSettled(toAdd.map((object) => addObjectToContainer({
      containerId,
      objectId: object.id,
      knowledgeGraph,
      paginationOptions,
      ...references,
    })));
    const added: CreatedObject[] = [];
    const failed: CreatedObject[] = [];
    results.forEach((result, index) => (result.status === 'fulfilled' ? added : failed).push(toAdd[index]));
    const resolvedAdded = await Promise.all(added.map((object) => (resolveObject
      ? resolveObject(object.id).catch(() => object)
      : Promise.resolve(object))));
    resolvedAdded.forEach((object) => argsRef.current.onAdded(object));
    if (failed.length > 0) {
      // The message names the failure; the objects added anyway can be unticked in the panel
      MESSAGING$.notifyError(t_i18n('{entityType} created, but could not be added to the {containerType}', {
        values: { entityType: t_i18n(`entity_${failed[0].entity_type}`), containerType: containerLabel() },
      }));
      return;
    }
    MESSAGING$.notifySuccess(addedMessage(added), { action: { label: 'Undo', onClick: () => { undo(added); } } });
  };

  const onCreated = (object: CreatedObject, options?: { withIndicator?: boolean }) => {
    if (argsRef.current.disabled) return;
    batchRef.current.push({ object, withIndicator: !!options?.withIndicator });
    if (timerRef.current) clearTimeout(timerRef.current);
    timerRef.current = setTimeout(() => {
      timerRef.current = null;
      flush();
    }, CREATED_OBJECTS_BATCH_DELAY_MS);
  };

  const submitReferences: FormikConfig<ReferencesFormValues>['onSubmit'] = (values, { setSubmitting, resetForm }) => {
    resolveReferences({
      commitMessage: values.message,
      references: (values.references ?? []).map((reference) => reference.value),
    });
    setSubmitting(false);
    resetForm();
  };

  const referencesDialog: ReactNode = args.enableReferences ? (
    <Formik<ReferencesFormValues> initialValues={{ message: '', references: [] }} onSubmit={submitReferences}>
      {({ submitForm, isSubmitting, setFieldValue, values }) => (
        <Form>
          <CommitMessage
            // Called on cancel, and after a submit (then already resolved)
            handleClose={() => resolveReferences(null)}
            open={referencesDialogOpen}
            submitForm={submitForm}
            disabled={isSubmitting}
            setFieldValue={setFieldValue}
            values={values.references}
            id={args.containerId}
            noStoreUpdate={true}
          />
        </Form>
      )}
    </Formik>
  ) : null;

  return { onCreated, referencesDialog };
};
