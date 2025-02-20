import DialogContent from '@mui/material/DialogContent';
import Typography from '@mui/material/Typography';
import Alert from '@mui/material/Alert';
import AlertTitle from '@mui/material/AlertTitle';
import FormGroup from '@mui/material/FormGroup';
import FormControlLabel from '@mui/material/FormControlLabel';
import Checkbox from '@mui/material/Checkbox';
import DialogActions from '@mui/material/DialogActions';
import Button from '@mui/material/Button';
import Dialog from '@mui/material/Dialog';
import React, { useState } from 'react';
import { Form, Formik } from 'formik';
import CommitMessage from '@components/common/form/CommitMessage';
import type { FormikConfig } from 'formik/dist/types';
import { Option } from '@components/common/form/ReferenceField';
import { knowledgeGraphQueryCheckObjectQuery } from '@components/common/containers/KnowledgeGraphQuery';
import { KnowledgeGraphQueryCheckObjectQuery$data } from '@components/common/containers/__generated__/KnowledgeGraphQueryCheckObjectQuery.graphql';
import Transition from '../../../components/Transition';
import { useFormatter } from '../../../components/i18n';
import { GraphContainer } from '../graph.types';
import { containerTypes } from '../../hooks/useAttributes';
import { useGraphContext } from '../GraphContext';
import { fetchQuery } from '../../../relay/environment';
import useKnowledgeGraphDeleteRelation from '../utils/useKnowledgeGraphDeleteRelation';
import useGraphInteractions from '../utils/useGraphInteractions';
import useKnowledgeGraphDeleteObject from '../utils/useKnowledgeGraphDeleteObject';

interface ReferenceFormData {
  message: string,
  references: Option[]
}

export interface GraphToolbarDeleteConfirmProps {
  open: boolean
  onClose: () => void
  enableReferences?: boolean
  container: GraphContainer
  onContainerDeleteRelation: (relId: string, onCompleted: () => void, message?: string, references?: string[]) => void
}

const GraphToolbarRemoveConfirm = ({
  open,
  onClose,
  enableReferences,
  container,
  onContainerDeleteRelation,
}: GraphToolbarDeleteConfirmProps) => {
  const { t_i18n } = useFormatter();
  const [andDelete, setAndDelete] = useState(false);
  const [referencesOpen, setReferencesOpen] = useState(false);

  const [commitDeleteRelKnowledgeGraph] = useKnowledgeGraphDeleteRelation();
  const [commitDeleteObjectKnowledgeGraph] = useKnowledgeGraphDeleteObject();

  const { selectedLinks, selectedNodes, graphData } = useGraphContext();
  const { clearSelection, removeLink, removeNode } = useGraphInteractions();

  const remove = (referencesValues?: ReferenceFormData) => {
    const ignoredStixCoreObjectsTypes = ['Note', 'Opinion'];
    // Containers checked when cascade delete.
    const checkedContainerTypes = containerTypes.filter((type) => {
      return !ignoredStixCoreObjectsTypes.includes(type);
    });

    // Remove links associated to removed nodes
    const selectedNodeIds = selectedNodes.map((n) => n.id);
    (graphData?.links ?? []).filter(({ source_id, target_id }) => {
      return selectedNodeIds.includes(source_id) || selectedNodeIds.includes(target_id);
    }).forEach(({ id }) => {
      onContainerDeleteRelation(
        id,
        () => removeLink(id),
        referencesValues?.message,
        referencesValues?.references.map((ref) => ref.value),
      );
    });

    // Remove selected nodes and links
    [...selectedNodes, ...selectedLinks].forEach(({ id }) => {
      const isNode = selectedNodeIds.includes(id);
      fetchQuery(knowledgeGraphQueryCheckObjectQuery, {
        id,
        entityTypes: checkedContainerTypes,
      }).toPromise().then((data) => {
        const result = data as KnowledgeGraphQueryCheckObjectQuery$data;
        if (
          andDelete
          && !result.stixObjectOrStixRelationship?.is_inferred
          && result.stixObjectOrStixRelationship?.containers?.edges?.length === 1
        ) {
          if (isNode) {
            commitDeleteObjectKnowledgeGraph({
              variables: { id },
              onCompleted: () => {
                removeNode(id);
              },
            });
          } else {
            commitDeleteRelKnowledgeGraph({
              variables: { id },
              onCompleted: () => {
                removeLink(id);
              },
            });
          }
        } else {
          onContainerDeleteRelation(
            id,
            () => {
              if (isNode) removeNode(id);
              else removeLink(id);
            },
            referencesValues?.message,
            referencesValues?.references.map((ref) => ref.value),
          );
        }
      });
    });

    clearSelection();
    onClose();
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
        PaperProps={{ elevation: 1 }}
        TransitionComponent={Transition}
        onClose={onClose}
      >
        <DialogContent>
          <Typography variant="body1">
            {t_i18n('Do you want to remove these elements?')}
          </Typography>
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
        </DialogContent>
        <DialogActions>
          <Button onClick={onClose}>
            {t_i18n('Cancel')}
          </Button>
          <Button color="secondary" onClick={confirm}>
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
                id={container.id}
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
