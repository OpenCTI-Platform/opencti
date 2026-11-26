import React, { ReactNode, useEffect, useRef, useState } from 'react';
import { Form, Formik, FormikConfig } from 'formik';
import { graphql } from 'react-relay';
import { fetchQuery, MESSAGING$ } from '../../../../relay/environment';
import { useFormatter } from '../../../../components/i18n';
import CommitMessage from '../form/CommitMessage';
import { ExternalReferencesValues } from '../form/ExternalReferencesField';
import { CreatedObject, useContainerObjects } from './useContainerObjects';
import { BulkCreationFeedback } from '../../../../utils/hooks/useCreationFeedback';
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

// A bulk creation in progress, from its start until its result dialog is closed
interface BulkState {
  // All its creations are done: no other object will come
  creationsDone: boolean;
  // Batches being added
  flushing: number;
  // Objects to add, and objects whose add is done (added or failed)
  total: number;
  done: number;
  added: CreatedObject[];
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
 * After a bulk creation, the confirmation is a line of the bulk result dialog instead: give `bulkCreation` to the creation forms
 * through `CreationFeedbackContext`.
 * Render `referencesDialog` outside the panel's drawer: Undo keeps working once the drawer is closed.
 */
export const useAddCreatedObjectsToContainer = (args: UseAddCreatedObjectsToContainerArgs) => {
  const { t_i18n } = useFormatter();
  const { addObjectToContainer, removeObjectFromContainer } = useContainerObjects();
  // The latest arguments: the batch is flushed after a delay, and Undo is clicked later
  const argsRef = useRef(args);
  argsRef.current = args;
  const mountedRef = useRef(true);
  const batchRef = useRef<CreatedObjectsBatchItem[]>([]);
  const timerRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const referencesResolverRef = useRef<((references: References | null) => void) | null>(null);
  const [referencesDialogOpen, setReferencesDialogOpen] = useState(false);
  const bulkRef = useRef<BulkState | null>(null);
  const [bulkProgress, setBulkProgress] = useState<BulkCreationFeedback['progress']>(null);
  const [bulkResultMessage, setBulkResultMessage] = useState<string | null>(null);

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

  // With a count even for a single object: the bulk result counts what was created the same way
  const addedMessage = (added: CreatedObject[], withCount = false) => {
    const values = { containerType: containerLabel(), count: added.length };
    if (added.length === 1 && !withCount) {
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

  // The bulk result dialog cannot be closed while objects may still be added
  const refreshBulkProgress = () => {
    const bulk = bulkRef.current;
    if (!bulk) return;
    setBulkProgress({
      done: bulk.done,
      total: bulk.total,
      inProgress: !bulk.creationsDone || timerRef.current !== null || bulk.flushing > 0,
    });
  };

  const flush = async () => {
    const bulk = bulkRef.current;
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
      const alreadyIn = t_i18n('Already in the {containerType}', { values: { containerType: containerLabel() } });
      if (created.length > 0 && bulkRef.current) {
        // The bulk result names what was added; this line only when nothing was
        if (bulkRef.current.added.length === 0) setBulkResultMessage(alreadyIn);
      } else if (created.length > 0) {
        MESSAGING$.notifySuccess(alreadyIn);
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
    if (bulk) {
      bulk.total += toAdd.length;
      refreshBulkProgress();
    }
    const results = await Promise.allSettled(toAdd.map((object) => addObjectToContainer({
      containerId,
      objectId: object.id,
      knowledgeGraph,
      paginationOptions,
      ...references,
    }).finally(() => {
      if (!bulk) return;
      bulk.done += 1;
      refreshBulkProgress();
    })));
    const added: CreatedObject[] = [];
    const failed: CreatedObject[] = [];
    results.forEach((result, index) => (result.status === 'fulfilled' ? added : failed).push(toAdd[index]));
    const resolvedAdded = await Promise.all(added.map((object) => (resolveObject
      ? resolveObject(object.id).catch(() => object)
      : Promise.resolve(object))));
    resolvedAdded.forEach((object) => argsRef.current.onAdded(object));
    // Read once the objects are added: if the bulk result dialog was closed meanwhile, the message below is shown
    const bulkAdded = bulkRef.current?.added;
    if (bulkAdded && added.length > 0) {
      bulkAdded.push(...added);
      setBulkResultMessage(addedMessage(bulkAdded, true));
    }
    if (failed.length > 0) {
      // The message names the failure; the objects added anyway can be unticked in the panel
      MESSAGING$.notifyError(t_i18n('{entityType} created, but could not be added to the {containerType}', {
        values: { entityType: t_i18n(`entity_${failed[0].entity_type}`), containerType: containerLabel() },
      }));
      return;
    }
    // The bulk result dialog already confirms the creation: its line replaces the message
    if (bulkAdded) return;
    MESSAGING$.notifySuccess(addedMessage(added), { action: { label: 'Undo', onClick: () => { undo(added); } } });
  };

  const onCreated = (object: CreatedObject, options?: { withIndicator?: boolean }) => {
    if (argsRef.current.disabled) return;
    batchRef.current.push({ object, withIndicator: !!options?.withIndicator });
    if (timerRef.current) clearTimeout(timerRef.current);
    timerRef.current = setTimeout(async () => {
      timerRef.current = null;
      const bulk = bulkRef.current;
      if (bulk) bulk.flushing += 1;
      try {
        await flush();
      } finally {
        if (bulk) bulk.flushing -= 1;
        refreshBulkProgress();
      }
    }, CREATED_OBJECTS_BATCH_DELAY_MS);
    refreshBulkProgress();
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

  // Nothing is added automatically when disabled: the bulk result keeps its own lines
  const bulkCreation: BulkCreationFeedback | undefined = args.disabled ? undefined : {
    onBulkStart: () => {
      bulkRef.current = { creationsDone: false, flushing: 0, total: 0, done: 0, added: [] };
      setBulkResultMessage(null);
      refreshBulkProgress();
    },
    onBulkCompleted: () => {
      const bulk = bulkRef.current;
      // After the last creation's onCreated, which its updater defers the same way
      setTimeout(() => {
        if (!bulk || bulkRef.current !== bulk) return;
        bulk.creationsDone = true;
        refreshBulkProgress();
      }, 0);
    },
    onBulkEnd: () => {
      bulkRef.current = null;
      setBulkProgress(null);
      setBulkResultMessage(null);
    },
    containerType: containerLabel(),
    progress: bulkProgress,
    resultMessage: bulkResultMessage,
  };

  return { onCreated, referencesDialog, bulkCreation };
};
