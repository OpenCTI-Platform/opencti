import React, { useState } from 'react';
import * as PropTypes from 'prop-types';
import * as R from 'ramda';
import { append, ascend, filter, map, pathOr, pipe, prop, sortWith, union } from 'ramda';
import { Field, Form, Formik } from 'formik';
import Typography from '@mui/material/Typography';
import Chip from '@mui/material/Chip';
import IconButton from '@mui/material/IconButton';
import Tooltip from '@mui/material/Tooltip';
import Dialog from '@mui/material/Dialog';
import DialogTitle from '@mui/material/DialogTitle';
import DialogContent from '@mui/material/DialogContent';
import DialogActions from '@mui/material/DialogActions';
import Button from '@mui/material/Button';
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

const useStyles = makeStyles(() => ({
  label: {
    margin: '0 7px 7px 0',
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
  const { t } = useFormatter();
  const { labels, marginTop, mutationRelationsAdd, mutationRelationDelete, enableReferences = false } = props;

  const isLabelManager = useGranted([SETTINGS_SETLABELS]);

  const [openAdd, setOpenAdd] = useState(false);
  const [openCreate, setOpenCreate] = useState(false);
  const [openCommitCreate, setOpenCommitCreate] = useState(false);
  const [openCommitDelete, setOpenCommitDelete] = useState(false);
  const [stateLabels, setStateLabels] = useState([]);
  const [labelInput, setLabelInput] = useState('');
  const [labelToDelete, setLabelToDelete] = useState(null);

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

  const searchLabels = (event) => {
    setLabelInput(event && event.target.value !== 0 ? event.target.value : '');
    fetchQuery(labelsSearchQuery, {
      search: event && event.target.value !== 0 ? event.target.value : '',
    })
      .toPromise()
      .then((data) => {
        const transformLabels = pipe(
          pathOr([], ['labels', 'edges']),
          map((n) => ({
            label: n.node.value,
            value: n.node.id,
            color: n.node.color,
          })),
        )(data);
        setStateLabels(union(stateLabels, transformLabels));
      });
  };

  const onSubmit = (values, { setSubmitting, resetForm }) => {
    const currentLabelsIds = map((label) => label.node.id, labels.edges);
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

  const labelsNodes = pipe(
    map((n) => n.node),
    sortWith([ascend(prop('value'))]),
  )(labels.edges);
  return (
    <div style={{ marginTop: marginTop || 0 }}>
      <Typography variant="h3" gutterBottom={true} style={{ float: 'left' }}>
        {t('Labels')}
      </Typography>
      <Security needs={[KNOWLEDGE_KNUPDATE]}>
        <IconButton
          color="secondary"
          aria-label="Label"
          onClick={handleOpenAdd}
          style={{ float: 'left', margin: '-15px 0 0 -2px' }}
          size="large"
        >
          <Add fontSize="small" />
        </IconButton>
      </Security>
      <div className="clearfix" />
      <div className={classes.objectLabel}>
        {map(
          (label) => (
            <Security
              needs={[KNOWLEDGE_KNUPDATE]}
              placeholder={
                <Tooltip title={label.value}>
                  <Chip
                    key={label.id}
                    variant="outlined"
                    classes={{ root: classes.label }}
                    label={truncate(label.value, 25)}
                    style={{
                      color: label.color,
                      borderColor: label.color,
                      backgroundColor: hexToRGB(label.color),
                    }}
                  />
                </Tooltip>
              }
            >
              <Tooltip title={label.value}>
                <Chip
                  key={label.id}
                  variant="outlined"
                  classes={{ root: classes.label }}
                  label={truncate(label.value, 25)}
                  style={{
                    color: label.color,
                    borderColor: label.color,
                    backgroundColor: hexToRGB(label.color),
                  }}
                  onDelete={() => (enableReferences ? handleOpenCommitDelete(label) : handleRemoveLabel(label.id))}
                  deleteIcon={
                    <CancelOutlined
                      className={classes.deleteIcon}
                      style={{ color: label.color }}
                    />
                  }
                />
              </Tooltip>
            </Security>
          ),
          labelsNodes,
        )}
        {enableReferences && (
          <Formik
            initialValues={{}}
            onSubmit={onSubmitDeleteLabel}
          >
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
            PaperProps={{ elevation: 1 }}
            open={openAdd}
            TransitionComponent={Transition}
            onClose={handleCloseAdd}
            fullWidth={true}
          >
            <DialogTitle>{t('Add new labels')}</DialogTitle>
            <DialogContent style={{ overflowY: 'hidden' }}>
              <Form>
                <Field
                  component={AutocompleteField}
                  name="new_labels"
                  multiple={true}
                  textfieldprops={{
                    variant: 'standard',
                    label: t('Labels'),
                    onFocus: searchLabels,
                  }}
                  noOptionsText={t('No available options')}
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
              <Button onClick={handleReset} disabled={isSubmitting}>
                {t('Close')}
              </Button>
              <Button
                onClick={enableReferences ? handleOpenCommitCreate : submitForm}
                disabled={isSubmitting}
                color="secondary"
              >
                {t('Add')}
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
                  handleClose={handleCloseCommitCreate} />
              )}
            </DialogActions>
            <LabelCreation
              contextual={true}
              open={openCreate}
              inputValue={labelInput}
              handleClose={handleCloseCreate}
              creationCallback={(data) => {
                setFieldValue(
                  'new_labels',
                  append(
                    {
                      label: data.labelAdd.value,
                      value: data.labelAdd.id,
                    },
                    values.new_labels,
                  ),
                );
              }}
            />
          </Dialog>
        )}
      </Formik>
    </div>
  );
};

StixCoreObjectOrCoreRelationshipLabelsView.propTypes = {
  id: PropTypes.string,
  labels: PropTypes.object,
  mutationRelationsAdd: PropTypes.func,
  mutationRelationDelete: PropTypes.func,
};

export default StixCoreObjectOrCoreRelationshipLabelsView;
