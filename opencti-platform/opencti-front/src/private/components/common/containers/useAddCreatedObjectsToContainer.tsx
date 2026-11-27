import React, { ReactNode, useEffect, useRef, useState } from 'react';
import { Form, Formik, FormikConfig } from 'formik';
import { graphql } from 'react-relay';
import { fetchQuery, MESSAGING$ } from '../../../../relay/environment';
import { useFormatter } from '../../../../components/i18n';
import CommitMessage from '../form/CommitMessage';
import { ExternalReferencesValues } from '../form/ExternalReferencesField';
import { CreatedObject, useContainerObjects } from './useContainerObjects';
import { BulkCreationFeedback } from '../../../../utils/hooks/useCreationFeedback';
import { useAddCreatedObjectsToContainerMembersQuery$data } from './__generated__/useAddCreatedObjectsToContainerMembersQuery.graphql';

/** The objects created within this delay of each other are added together, with a single message. */
export const CREATED_OBJECTS_BATCH_DELAY_MS = 1000;

// Which of the given objects are in the container: the panels load only its first objects
const containerMembersQuery = graphql`
  query useAddCreatedObjectsToContainerMembersQuery($id: String!, $filters: FilterGroup, $count: Int) {
    container(id: $id) {
      objects(filters: $filters, first: $count) {
        edges {
          node {
            ... on BasicObject {
              id
            }
            ... on BasicRelationship {
              id
            }
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
  // The indicator created with an observable ("Create indicator"), as the creation returned it
  indicator: CreatedObject | null;
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

const fetchContainerMemberIds = async (containerId: string, objectIds: string[]): Promise<string[]> => {
  const filters = {
    mode: 'and',
    filterGroups: [],
    filters: [{ key: 'ids', operator: 'eq', mode: 'or', values: objectIds }],
  };
  const data = await fetchQuery(containerMembersQuery, { id: containerId, filters, count: objectIds.length })
    .toPromise() as useAddCreatedObjectsToContainerMembersQuery$data;
  return (data?.container?.objects?.edges ?? []).flatMap((edge) => (edge?.node?.id ? [edge.node.id] : []));
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
  const pendingReferencesRef = useRef<Promise<References | null> | null>(null);
  const [referencesDialogOpen, setReferencesDialogOpen] = useState(false);
  const bulkRef = useRef<BulkState | null>(null);
  const [bulkProgress, setBulkProgress] = useState<BulkCreationFeedback['progress']>(null);
  const [bulkResultMessage, setBulkResultMessage] = useState<string | null>(null);

  useEffect(() => {
    mountedRef.current = true;
    return () => {
      mountedRef.current = false;
      // The references dialog is gone with the panel: a request waiting for it is cancelled
      const resolve = referencesResolverRef.current;
      referencesResolverRef.current = null;
      pendingReferencesRef.current = null;
      resolve?.(null);
      // The form cannot end a bulk creation anymore: what it created is added, or the cancellation is warned, as after any creation
      bulkRef.current = null;
      flushHeldObjects();
    };
  }, []);

  const containerLabel = () => {
    const { containerType } = argsRef.current;
    return containerType ? t_i18n(`entity_${containerType}`) : t_i18n('container');
  };

  // A request made while the dialog is open waits for that dialog: one set of references for all of them
  // Without the panel, there is no dialog to ask them: the request is cancelled
  const askReferences = () => {
    if (!mountedRef.current) return Promise.resolve(null);
    if (!pendingReferencesRef.current) {
      pendingReferencesRef.current = new Promise<References | null>((resolve) => {
        referencesResolverRef.current = resolve;
        setReferencesDialogOpen(true);
      });
    }
    return pendingReferencesRef.current;
  };
  const resolveReferences = (references: References | null) => {
    const resolve = referencesResolverRef.current;
    referencesResolverRef.current = null;
    pendingReferencesRef.current = null;
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
    // The indicator created with an observable ("Create indicator") is added too
    const indicators = batch.flatMap((item) => (item.indicator ? [item.indicator] : []));
    const created = [...batch.map((item) => item.object), ...indicators]
      .filter((object, index, all) => all.findIndex((o) => o.id === object.id) === index);
    // An existing object returned by the creation (upsert) may already be in the container: it is neither added nor undone.
    // The panel knows only the first objects of the container: the server is asked for the others.
    const unknown = created.filter((object) => !isInContainer(object.id));
    const memberIds = unknown.length > 0
      ? await fetchContainerMemberIds(containerId, unknown.map((object) => object.id)).catch(() => [])
      : [];
    const toAdd = unknown.filter((object) => !memberIds.includes(object.id));
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
      objectTypes: [object.entity_type, ...(object.parent_types ?? [])],
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
    MESSAGING$.notifySuccess(addedMessage(added), {
      action: {
        label: 'Undo',
        onClick: () => {
          undo(added);
        },
      },
    });
  };

  const runFlush = async () => {
    const bulk = bulkRef.current;
    if (bulk) bulk.flushing += 1;
    try {
      await flush();
    } finally {
      if (bulk) bulk.flushing -= 1;
      refreshBulkProgress();
    }
  };

  const onCreated = (object: CreatedObject, options?: { indicator?: CreatedObject | null }) => {
    if (argsRef.current.disabled) return;
    batchRef.current.push({ object, indicator: options?.indicator ?? null });
    if (timerRef.current) clearTimeout(timerRef.current);
    timerRef.current = null;
    // The objects of a bulk creation are added together once all are created: one add, one references dialog
    const bulk = bulkRef.current;
    if (!bulk || bulk.creationsDone) {
      timerRef.current = setTimeout(() => {
        timerRef.current = null;
        runFlush();
      }, CREATED_OBJECTS_BATCH_DELAY_MS);
    }
    refreshBulkProgress();
  };

  // Adds the objects held during a bulk creation
  const flushHeldObjects = () => {
    if (batchRef.current.length > 0 && !timerRef.current) runFlush();
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
        flushHeldObjects();
        refreshBulkProgress();
      }, 0);
    },
    onBulkEnd: () => {
      bulkRef.current = null;
      setBulkProgress(null);
      setBulkResultMessage(null);
      // Closed before all were created (e.g. the form is gone): what was created is still added, with a message
      flushHeldObjects();
    },
    containerType: containerLabel(),
    progress: bulkProgress,
    resultMessage: bulkResultMessage,
  };

  return { onCreated, referencesDialog, bulkCreation };
};
