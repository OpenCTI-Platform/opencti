import Typography from '@mui/material/Typography';
import Alert from '@mui/material/Alert';
import AlertTitle from '@mui/material/AlertTitle';
import Stack from '@mui/material/Stack';
import DialogActions from '@mui/material/DialogActions';
import Button from '@common/button/Button';
import Dialog from '@common/dialog/Dialog';
import React, { useState } from 'react';
import { Form, Formik } from 'formik';
import CommitMessage from '@components/common/form/CommitMessage';
import type { FormikConfig } from 'formik/dist/types';
import { knowledgeGraphQueryCheckObjectQuery } from '@components/common/containers/KnowledgeGraphQuery';
import { KnowledgeGraphQueryCheckObjectQuery$data } from '@components/common/containers/__generated__/KnowledgeGraphQueryCheckObjectQuery.graphql';
import { LinearProgress } from '@mui/material';
import { useTheme } from '@mui/material/styles';
import { useFormatter } from '../../i18n';
import { containerTypes } from '../../../utils/hooks/useAttributes';
import { useGraphContext } from '../GraphContext';
import { fetchQuery } from '../../../relay/environment';
import useKnowledgeGraphDeleteRelation from '../utils/useKnowledgeGraphDeleteRelation';
import useGraphInteractions from '../utils/useGraphInteractions';
import useKnowledgeGraphDeleteObject from '../utils/useKnowledgeGraphDeleteObject';
import { FieldOption } from '../../../utils/field';
import type { Theme } from '../../Theme';
import { isGraphNode } from '../graph.types';
import { Checkbox } from '@filigran/design-system';

interface ReferenceFormData {
  message: string;
  references: FieldOption[];
}

export interface GraphToolbarDeleteConfirmProps {
  open: boolean;
  onClose: () => void;
  enableReferences?: boolean;
  entityId: string;
  onDeleteRelation?: (relId: string, onCompleted: () => void, message?: string, references?: string[]) => void;
  onRemove?: (ids: string[], onCompleted: () => void) => void;
}

const GraphToolbarRemoveConfirm = ({
  open,
  onClose,
  enableReferences,
  entityId,
  onDeleteRelation,
  onRemove,
}: GraphToolbarDeleteConfirmProps) => {
  const theme = useTheme<Theme>();
  const { t_i18n } = useFormatter();
  const [andDelete, setAndDelete] = useState(false);
  const [referencesOpen, setReferencesOpen] = useState(false);

  const [totalToDelete, setTotalToDelete] = useState(0);
  const [currentDeleted, setCurrentDeleted] = useState(0);

  const [commitDeleteRelKnowledgeGraph] = useKnowledgeGraphDeleteRelation();
  const [commitDeleteObjectKnowledgeGraph] = useKnowledgeGraphDeleteObject();

  const {
    context,
    graphData,
    graphState: {
      selectedLinks,
      selectedNodes,
    },
  } = useGraphContext();

  const close = () => {
    setTotalToDelete(0);
    setCurrentDeleted(0);
    setAndDelete(false);
    onClose();
  };

  const {
    clearSelection,
    removeLinks,
    removeNodes,
  } = useGraphInteractions();

  const promiseDeleteRel = async (id: string) => {
    return new Promise((resolve) => {
      commitDeleteRelKnowledgeGraph({
        variables: { id },
        onCompleted: () => resolve(id),
      });
    });
  };

  const promiseDeleteObject = async (id: string) => {
    return new Promise((resolve) => {
      commitDeleteObjectKnowledgeGraph({
        variables: { id },
        onCompleted: () => resolve(id),
      });
    });
  };

  const promiseOnDeleteRelation = async (
    relId: string,
    message?: string,
    references?: string[],
  ) => {
    return new Promise((resolve) => {
      onDeleteRelation?.(
        relId,
        () => resolve(relId),
        message,
        references,
      );
    });
  };

  // Links attached to a selected node go with it. A link both selected and attached
  // is counted once, so it is never removed twice.
  const selectedNodeIds = selectedNodes.map((n) => n.id);
  const selectedLinkIds = selectedLinks.map((l) => l.id);
  const associatedLinks = (graphData?.links ?? []).filter(({ id, source_id, target_id }) => {
    return !selectedLinkIds.includes(id)
      && (selectedNodeIds.includes(source_id) || selectedNodeIds.includes(target_id));
  });

  const removeKnowledge = async (referencesValues?: ReferenceFormData) => {
    const nodesToRemove: string[] = [];
    const linksToRemove: string[] = [];

    const allSelection = [...selectedNodes, ...selectedLinks];

    setTotalToDelete(allSelection.length + associatedLinks.length);

    // Remove selected nodes and links
    // /!\ We are voluntary using await in loop to call API
    // sequentially to avoid lock issues when deleting.
    for (const el of allSelection) {
      const { id } = el;
      const isNode = isGraphNode(el);

      const data = (await fetchQuery(
        knowledgeGraphQueryCheckObjectQuery,
        { id, entityTypes: containerTypes },
      ).toPromise()) as KnowledgeGraphQueryCheckObjectQuery$data;
      if (
        andDelete
        && !data.stixObjectOrStixRelationship?.is_inferred
        && data.stixObjectOrStixRelationship?.containers?.edges?.length === 1
      ) {
        if (isNode) {
          await promiseDeleteObject(id);
          nodesToRemove.push(id);
          setCurrentDeleted((old) => old + 1);
        } else {
          await promiseDeleteRel(id);
          linksToRemove.push(id);
          setCurrentDeleted((old) => old + 1);
        }
      } else {
        await promiseOnDeleteRelation(
          id,
          referencesValues?.message,
          referencesValues?.references.map((ref) => ref.value),
        );
        if (isNode) nodesToRemove.push(id);
        else linksToRemove.push(id);
        setCurrentDeleted((old) => old + 1);
      }
    }

    // Remove links associated to removed nodes
    // /!\ We are voluntary using await in loop to call API
    // sequentially to avoid lock issues when deleting.
    for (const { id } of associatedLinks) {
      await promiseOnDeleteRelation(
        id,
        referencesValues?.message,
        referencesValues?.references.map((ref) => ref.value),
      );
      linksToRemove.push(id);
      setCurrentDeleted((old) => old + 1);
    }

    removeNodes(nodesToRemove);
    removeLinks(linksToRemove);
    clearSelection();
    close();
  };

  const remove = (referencesValues?: ReferenceFormData) => {
    if (!onRemove) {
      removeKnowledge(referencesValues);
    } else {
      const correlatedLinksIds = associatedLinks.map((l) => l.id);
      onRemove(
        [...selectedNodeIds, ...selectedLinkIds, ...correlatedLinksIds],
        () => {
          removeNodes(selectedNodeIds);
          removeLinks([...selectedLinkIds, ...correlatedLinksIds]);
        },
      );
      clearSelection();
      close();
    }
  };

  const confirm = () => {
    if (!enableReferences) remove();
    else setReferencesOpen(true);
  };

  const confirmWithReference: FormikConfig<ReferenceFormData>['onSubmit'] = (
    values,
    { resetForm },
  ) => {
    remove(values);
    resetForm();
  };

  return (
    <>
      <Dialog
        open={open}
        size="small"
        onClose={close}
        title={t_i18n('Do you want to remove these elements?')}
      >
        <Typography>
          {t_i18n('{entitiesCount} entities and {relationshipsCount} relationships will be removed, including the relationships attached to the selected entities.', {
            values: {
              entitiesCount: selectedNodes.length,
              relationshipsCount: selectedLinks.length + associatedLinks.length,
            },
          })}
        </Typography>
        {context !== 'investigation' && (
          <Alert
            severity="warning"
            variant="outlined"
            style={{ marginTop: 20 }}
          >
            {/* Same layout as ReportDeletion: the message slot scrolls and clips its edges,
                so the inset keeps the box and the focus ring painted outside it in view. */}
            <Stack spacing={1} pl={1}>
              <AlertTitle>{t_i18n('Cascade delete')}</AlertTitle>
              {/* The library Checkbox carries its own label: a MUI FormControlLabel pulls its
                  control 11px left for MUI's padding, which clipped this box out of sight. */}
              <Checkbox
                label={t_i18n('Delete the element if no other containers contain it')}
                checked={andDelete}
                onCheckedChange={() => setAndDelete((d) => !d)}
              />
            </Stack>
          </Alert>
        )}

        {totalToDelete > 0 && (
          <div
            style={{
              marginTop: theme.spacing(1),
              display: 'flex',
              gap: theme.spacing(1),
              alignItems: 'center',
            }}
          >
            <LinearProgress
              style={{ flex: 1 }}
              variant="determinate"
              value={(currentDeleted / totalToDelete) * 100}
            />
            <Typography style={{ flexShrink: 0 }}>
              {currentDeleted} / {totalToDelete}
            </Typography>
          </div>
        )}
        <DialogActions>
          <Button variant="secondary" onClick={close} disabled={totalToDelete > 0}>
            {t_i18n('Cancel')}
          </Button>
          <Button onClick={confirm} disabled={totalToDelete > 0}>
            {t_i18n('Remove')}
          </Button>
        </DialogActions>
      </Dialog>

      {enableReferences && (
        <Formik<ReferenceFormData>
          initialValues={{ message: '', references: [] }}
          onSubmit={confirmWithReference}
        >
          {({ submitForm, isSubmitting, setFieldValue, values }) => (
            <Form>
              <CommitMessage
                handleClose={() => setReferencesOpen(false)}
                open={referencesOpen}
                submitForm={submitForm}
                disabled={isSubmitting}
                setFieldValue={setFieldValue}
                values={values.references}
                id={entityId}
                noStoreUpdate={true}
              />
            </Form>
          )}
        </Formik>
      )}
    </>
  );
};

export default GraphToolbarRemoveConfirm;
