import React, { useState } from 'react';
import * as PropTypes from 'prop-types';
import * as R from 'ramda';
import { filter, map, pipe } from 'ramda';
import { Field, Form, Formik } from 'formik';
import Chip from '@mui/material/Chip';
import Tooltip from '@mui/material/Tooltip';
import Dialog from '@mui/material/Dialog';
import DialogTitle from '@mui/material/DialogTitle';
import DialogContent from '@mui/material/DialogContent';
import DialogActions from '@mui/material/DialogActions';
import Button from '@common/button/Button';
import IconButton from '@common/button/IconButton';
import { Add, CancelOutlined } from '@mui/icons-material';
import { Label } from 'mdi-material-ui';
import makeStyles from '@mui/styles/makeStyles';
import { commitMutation, fetchQuery } from '../../../../relay/environment';
import { useFormatter } from '../../../../components/i18n';
import { labelsSearchQuery } from '../../settings/LabelsQuery';
import AutocompleteField from '../../../../components/AutocompleteField';
import LabelCreation from '../../settings/labels/LabelCreation';
import Security from '../../../../utils/Security';
import { hexToRGB } from '../../../../utils/Colors';
import { truncate } from '../../../../utils/String';
import useGranted, { KNOWLEDGE_KNUPDATE, SETTINGS_SETLABELS } from '../../../../utils/hooks/useGranted';
import CommitMessage from '../form/CommitMessage';
import Transition from '../../../../components/Transition';
import FieldOrEmpty from '../../../../components/FieldOrEmpty';
import CardLabel from '../../../../components/CardLabel';

// Deprecated - https://mui.com/system/styles/basics/
// Do not use it for new code.
const useStyles = makeStyles(() => ({
  label: {
    margin: '0 7px 7px 0',
    borderRadius: 4,
  },
  labelMore: {
    margin: '0 7px 7px 0',
    borderRadius: 4,
    cursor: 'pointer',
  },
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
      <CardLabel
        style={{ marginTop: 20 }}
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
      </CardLabel>
      <div className={classes.objectLabel}>
        <FieldOrEmpty source={labels}>
          {map(
            (label) => (
              <Tooltip key={label.id} title={label.value}>
                <Chip
                  variant="outlined"
                  classes={{ root: classes.label }}
                  label={truncate(label.value, 25)}
                  style={{
                    color: label.color,
                    borderColor: label.color,
                    backgroundColor: hexToRGB(label.color),
                  }}
                  onDelete={canUpdateKnowledge ? () => (enableReferences
                    ? handleOpenCommitDelete(label)
                    : handleRemoveLabel(label.id)) : undefined}
                  deleteIcon={(
                    <CancelOutlined
                      className={classes.deleteIcon}
                      style={{ color: label.color }}
                    />
                  )}
                />
              </Tooltip>
            ),
            (labels ? R.take(12, labels) : []),
          )}
          {labels && labels.length > 12 && (
            <Tooltip title={t_i18n('See more')}>
              <Chip
                variant="outlined"
                classes={{ root: classes.labelMore }}
                label="..."
                onClick={handleOpenLabels}
              />
            </Tooltip>
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
              <DialogContent>
                {map(
                  (label) => (
                    <Tooltip key={label.id} title={label.value}>
                      <Chip
                        variant="outlined"
                        classes={{ root: classes.label }}
                        label={truncate(label.value, 25)}
                        style={{
                          color: label.color,
                          borderColor: label.color,
                          backgroundColor: hexToRGB(label.color),
                        }}
                        onDelete={canUpdateKnowledge ? () => (enableReferences
                          ? handleOpenCommitDelete(label)
                          : handleRemoveLabel(label.id)) : undefined}
                        deleteIcon={(
                          <CancelOutlined
                            className={classes.deleteIcon}
                            style={{ color: label.color }}
                          />
                        )}
                      />
                    </Tooltip>
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
