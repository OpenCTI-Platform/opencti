import DialogContent from '@mui/material/DialogContent';
import Typography from '@mui/material/Typography';
import Alert from '@mui/material/Alert';
import AlertTitle from '@mui/material/AlertTitle';
import FormGroup from '@mui/material/FormGroup';
import FormControlLabel from '@mui/material/FormControlLabel';
import Checkbox from '@mui/material/Checkbox';
import DialogActions from '@mui/material/DialogActions';
import Button from '@common/button/Button';
import Dialog from '@mui/material/Dialog';
import React, { useState } from 'react';
import { Form, Formik } from 'formik';
import CommitMessage from '@components/common/form/CommitMessage';
import type { FormikConfig } from 'formik/dist/types';
import { knowledgeGraphQueryCheckObjectQuery } from '@components/common/containers/KnowledgeGraphQuery';
import { KnowledgeGraphQueryCheckObjectQuery$data } from '@components/common/containers/__generated__/KnowledgeGraphQueryCheckObjectQuery.graphql';
import { LinearProgress } from '@mui/material';
import { useTheme } from '@mui/material/styles';
import Transition from '../../Transition';
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

  const removeKnowledge = async (referencesValues?: ReferenceFormData) => {
    const nodesToRemove: string[] = [];
    const linksToRemove: string[] = [];

    const ignoredStixCoreObjectsTypes = ['Note', 'Opinion'];
    // Containers checked when cascade delete.
    const checkedContainerTypes = containerTypes.filter((type) => {
      return !ignoredStixCoreObjectsTypes.includes(type);
    });

    const allSelection = [...selectedNodes, ...selectedLinks];
    const selectedNodeIds = selectedNodes.map((n) => n.id);
    const associatedLinks = (graphData?.links ?? []).filter(({ source_id, target_id }) => {
      return selectedNodeIds.includes(source_id) || selectedNodeIds.includes(target_id);
    });

    setTotalToDelete(allSelection.length + associatedLinks.length);

    // Remove selected nodes and links
    // /!\ We are voluntary using await in loop to call API
    // sequentially to avoid lock issues when deleting.
    for (const el of allSelection) {
      const { id } = el;
      const isNode = isGraphNode(el);

      const data = (await fetchQuery(
        knowledgeGraphQueryCheckObjectQuery,
        { id, entityTypes: checkedContainerTypes },
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
      const nodesIds = selectedNodes.map((s) => s.id);
      const linksIds = selectedLinks.map((s) => s.id);
      const correlatedLinksIds = (graphData?.links ?? []).filter((l) => {
        return nodesIds.includes(l.source_id) || nodesIds.includes(l.target_id);
      }).map((l) => l.id);
      onRemove(
        [...nodesIds, ...linksIds, ...correlatedLinksIds],
        () => {
          removeNodes(nodesIds);
          removeLinks([...linksIds, ...correlatedLinksIds]);
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
        keepMounted
        slotProps={{ paper: { elevation: 1 } }}
        slots={{ transition: Transition }}
        onClose={close}
      >
        <DialogContent>
          <Typography variant="body1">
            {t_i18n('Do you want to remove these elements?')}
          </Typography>
          {context !== 'investigation' && (
            <Alert
              severity="warning"
              variant="outlined"
              style={{ marginTop: 20 }}
            >
              <AlertTitle>{t_i18n('Cascade delete')}</AlertTitle>
              <FormGroup>
                <FormControlLabel
                  label={t_i18n('Delete the element if no other containers contain it')}
                  control={(
                    <Checkbox
                      checked={andDelete}
                      onChange={() => setAndDelete((d) => !d)}
                    />
                  )}
                />
              </FormGroup>
            </Alert>
          )
          }

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
        </DialogContent>
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
