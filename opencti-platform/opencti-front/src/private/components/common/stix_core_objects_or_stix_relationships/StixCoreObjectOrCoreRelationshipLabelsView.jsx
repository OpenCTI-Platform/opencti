import Button from '@common/button/Button';
import IconButton from '@common/button/IconButton';
import CardTitle from '@common/card/CardTitle';
import Tag from '@common/tag/Tag';
import { Add } from '@mui/icons-material';
import Dialog from '@mui/material/Dialog';
import DialogActions from '@mui/material/DialogActions';
import DialogContent from '@mui/material/DialogContent';
import DialogTitle from '@mui/material/DialogTitle';
import makeStyles from '@mui/styles/makeStyles';
import { Field, Form, Formik } from 'formik';
import { Label } from 'mdi-material-ui';
import * as PropTypes from 'prop-types';
import * as R from 'ramda';
import { filter, map, pipe } from 'ramda';
import { useState } from 'react';
import AutocompleteField from '../../../../components/AutocompleteField';
import FieldOrEmpty from '../../../../components/FieldOrEmpty';
import Transition from '../../../../components/Transition';
import { useFormatter } from '../../../../components/i18n';
import { commitMutation, fetchQuery } from '../../../../relay/environment';
import Security from '../../../../utils/Security';
import useGranted, { KNOWLEDGE_KNUPDATE, SETTINGS_SETLABELS } from '../../../../utils/hooks/useGranted';
import { labelsSearchQuery } from '../../settings/LabelsQuery';
import LabelCreation from '../../settings/labels/LabelCreation';
import CommitMessage from '../form/CommitMessage';

// Deprecated - https://mui.com/system/styles/basics/
// Do not use it for new code.
const useStyles = makeStyles(() => ({
  icon: {
    paddingTop: 4,
    display: 'inline-block',
  },
  text: {
    display: 'inline-block',
    flexGrow: 1,
    marginLeft: 10,
  },
  autoCompleteIndicator: {
    display: 'none',
  },
}));

const StixCoreObjectOrCoreRelationshipLabelsView = (props) => {
  const classes = useStyles();
  const { t_i18n } = useFormatter();
  const {
    labels,
    mutationRelationsAdd,
    mutationRelationDelete,
    enableReferences = false,
  } = props;

  const isLabelManager = useGranted([SETTINGS_SETLABELS]);
  const canUpdateKnowledge = useGranted([KNOWLEDGE_KNUPDATE]);

  const [openAdd, setOpenAdd] = useState(false);
  const [openCreate, setOpenCreate] = useState(false);
  const [openCommitCreate, setOpenCommitCreate] = useState(false);
  const [openCommitDelete, setOpenCommitDelete] = useState(false);
  const [stateLabels, setStateLabels] = useState([]);
  const [labelInput, setLabelInput] = useState('');
  const [labelToDelete, setLabelToDelete] = useState(null);
  const [openLabels, setOpenLabels] = useState(false);

  const handleOpenAdd = () => setOpenAdd(true);
  const handleCloseAdd = () => setOpenAdd(false);
  const handleOpenCreate = () => setOpenCreate(true);
  const handleCloseCreate = () => setOpenCreate(false);
  const handleOpenCommitCreate = () => setOpenCommitCreate(true);
  const handleCloseCommitCreate = () => setOpenCommitCreate(false);
  const handleOpenCommitDelete = (label) => {
    setOpenCommitDelete(true);
    setLabelToDelete(label);
  };
  const handleCloseCommitDelete = () => setOpenCommitDelete(false);
  const handleOpenLabels = () => setOpenLabels(true);
  const handleCloseLabels = () => setOpenLabels(false);

  const searchLabels = async (event) => {
    setLabelInput(event && event.target.value !== 0 ? event.target.value : '');

    const data = await fetchQuery(labelsSearchQuery, {
      search: event && event.target.value !== 0 ? event.target.value : '',
      orderBy: 'value',
      orderMode: 'asc',
    }).toPromise();

    const edges = data?.labels?.edges ?? [];
    const labelOptions = edges.map((n) => ({
      label: n.node.value,
      value: n.node.id,
      color: n.node.color,
    }));

    setStateLabels(labelOptions);
  };

  const onSubmit = (values, { setSubmitting, resetForm }) => {
    const currentLabelsIds = (labels ?? []).map((label) => label.id);
    const labelsIds = pipe(
      map((value) => value.value),
      filter((value) => !currentLabelsIds.includes(value)),
    )(values.new_labels);
    commitMutation({
      mutation: mutationRelationsAdd,
      variables: {
        id: props.id,
        input: {
          toIds: labelsIds,
          relationship_type: 'object-label',
        },
        commitMessage: values.message,
        references: R.pluck('value', values.references || []),
      },
      setSubmitting,
      onCompleted: () => {
        setSubmitting(false);
        resetForm();
        handleCloseCommitCreate();
        handleCloseAdd();
      },
    });
  };

  const handleRemoveLabel = (labelId, values = {}) => {
    commitMutation({
      mutation: mutationRelationDelete,
      variables: {
        id: props.id,
        toId: labelId,
        relationship_type: 'object-label',
        commitMessage: values.message,
        references: R.pluck('value', values.references || []),
      },
    });
  };

  const onSubmitDeleteLabel = (values, { resetForm }) => {
    handleRemoveLabel(labelToDelete.id, values);
    setOpenCommitDelete(false);
    setLabelToDelete(null);
    resetForm();
  };

  const onReset = () => setOpenAdd(false);

  return (
    <>
      <CardTitle
        sx={{ marginTop: '20px' }}
        action={(
          <Security needs={[KNOWLEDGE_KNUPDATE]}>
            <IconButton
              size="small"
              variant="tertiary"
              aria-label={t_i18n('Add new labels')}
              title={t_i18n('Add new labels')}
              onClick={handleOpenAdd}
            >
              <Add fontSize="small" />
            </IconButton>
          </Security>
        )}
      >
        {t_i18n('Labels')}
      </CardTitle>
      <div className={classes.objectLabel} style={{ display: 'flex', flexDirection: 'row', flexWrap: 'wrap', gap: '8px' }}>
        <FieldOrEmpty source={labels}>
          {map(
            (label) => (
              <Tag
                key={label.id}
                label={label.value}
                color={label.color}
                onDelete={canUpdateKnowledge ? () => (
                  enableReferences
                    ? handleOpenCommitDelete(label)
                    : handleRemoveLabel(label.id)
                ) : undefined
                }
              />
            ),
            (labels ? R.take(12, labels) : []),
          )}
          {labels && labels.length > 12 && (
            <Tag
              tooltipTitle={t_i18n('See more')}
              label="..."
              onClick={handleOpenLabels}
            />
          )}
          {labels && labels.length > 12 && (
            <Dialog
              slotProps={{ paper: { elevation: 1 } }}
              open={openLabels}
              slots={{ transition: Transition }}
              onClose={handleCloseLabels}
              fullWidth={true}
              maxWidth="md"
            >
              <DialogTitle>{t_i18n('All labels')}</DialogTitle>
              <DialogContent sx={{ display: 'flex', flexWrap: 'wrap', gap: 1 }}>
                {map(
                  (label) => (
                    <Tag
                      key={label.id}
                      label={label.value}
                      color={label.color}
                      onDelete={canUpdateKnowledge ? () => (
                        enableReferences
                          ? handleOpenCommitDelete(label)
                          : handleRemoveLabel(label.id)
                      ) : undefined
                      }
                    />
                  ),
                  labels,
                )}
              </DialogContent>
              <DialogActions>
                <Button onClick={handleCloseLabels}>
                  {t_i18n('Close')}
                </Button>
              </DialogActions>
            </Dialog>
          )}
        </FieldOrEmpty>
        {enableReferences && (
          <Formik initialValues={{}} onSubmit={onSubmitDeleteLabel}>
            {({ submitForm, isSubmitting, setFieldValue, values }) => (
              <Form>
                <CommitMessage
                  handleClose={handleCloseCommitDelete}
                  open={openCommitDelete}
                  submitForm={submitForm}
                  disabled={isSubmitting}
                  setFieldValue={setFieldValue}
                  values={values.references}
                  id={props.id}
                />
              </Form>
            )}
          </Formik>
        )}
      </div>
      <Formik
        initialValues={{ new_labels: [] }}
        onSubmit={onSubmit}
        onReset={onReset}
      >
        {({ submitForm, handleReset, isSubmitting, setFieldValue, values }) => (
          <Dialog
            slotProps={{ paper: { elevation: 1 } }}
            open={openAdd}
            slots={{ transition: Transition }}
            onClose={handleCloseAdd}
            fullWidth={true}
          >
            <DialogTitle>{t_i18n('Add new labels')}</DialogTitle>
            <DialogContent style={{ overflowY: 'hidden' }}>
              <Form>
                <Field
                  component={AutocompleteField}
                  name="new_labels"
                  multiple={true}
                  textfieldprops={{
                    variant: 'standard',
                    label: t_i18n('Labels'),
                    onFocus: searchLabels,
                  }}
                  noOptionsText={t_i18n('No available options')}
                  options={stateLabels}
                  onInputChange={searchLabels}
                  openCreate={isLabelManager ? handleOpenCreate : null}
                  renderOption={(optionsProps, option) => (
                    <li {...optionsProps}>
                      <div
                        className={classes.icon}
                        style={{ color: option.color }}
                      >
                        <Label />
                      </div>
                      <div className={classes.text}>{option.label}</div>
                    </li>
                  )}
                  classes={{ clearIndicator: classes.autoCompleteIndicator }}
                />
              </Form>
            </DialogContent>
            <DialogActions>
              <Button variant="secondary" onClick={handleReset} disabled={isSubmitting}>
                {t_i18n('Close')}
              </Button>
              <Button
                onClick={enableReferences ? handleOpenCommitCreate : submitForm}
                disabled={isSubmitting}
              >
                {t_i18n('Add')}
              </Button>
              {enableReferences && (
                <CommitMessage
                  submitForm={submitForm}
                  disabled={isSubmitting}
                  setFieldValue={setFieldValue}
                  values={values.references}
                  id={props.id}
                  noStoreUpdate={true}
                  open={openCommitCreate}
                  handleClose={handleCloseCommitCreate}
                />
              )}
            </DialogActions>
            <LabelCreation
              contextual={true}
              open={openCreate}
              inputValue={labelInput}
              handleClose={handleCloseCreate}
              creationCallback={(data) => {
                const newLabel = {
                  label: data.labelAdd.value,
                  value: data.labelAdd.id,
                };
                setFieldValue('new_labels', [...values.new_labels, newLabel]);
              }}
            />
          </Dialog>
        )}
      </Formik>
    </>
  );
};

StixCoreObjectOrCoreRelationshipLabelsView.propTypes = {
  id: PropTypes.string,
  labels: PropTypes.array,
  mutationRelationsAdd: PropTypes.object,
  mutationRelationDelete: PropTypes.object,
};

export default StixCoreObjectOrCoreRelationshipLabelsView;
