import React, { useContext, useState } from 'react';
import * as PropTypes from 'prop-types';
import {
  compose,
  map,
  pathOr,
  pipe,
  union,
  append,
  filter,
  sortWith,
  ascend,
  prop,
} from 'ramda';
import { Form, Formik, Field } from 'formik';
import { graphql } from 'react-relay';
import withStyles from '@mui/styles/withStyles';
import Typography from '@mui/material/Typography';
import Chip from '@mui/material/Chip';
import IconButton from '@mui/material/IconButton';
import Tooltip from '@mui/material/Tooltip';
import Dialog from '@mui/material/Dialog';
import DialogTitle from '@mui/material/DialogTitle';
import DialogContent from '@mui/material/DialogContent';
import DialogActions from '@mui/material/DialogActions';
import Button from '@mui/material/Button';
import Slide from '@mui/material/Slide';
import { Add, CancelOutlined } from '@mui/icons-material';
import { Label } from 'mdi-material-ui';
import { commitMutation, fetchQuery } from '../../../../relay/environment';
import inject18n from '../../../../components/i18n';
import { labelsSearchQuery } from '../../settings/LabelsQuery';
import AutocompleteField from '../../../../components/AutocompleteField';
import LabelCreation from '../../settings/labels/LabelCreation';
import Security, {
  granted,
  KNOWLEDGE_KNUPDATE,
  SETTINGS_SETLABELS,
  UserContext,
} from '../../../../utils/Security';
import { hexToRGB } from '../../../../utils/Colors';
import { truncate } from '../../../../utils/String';

const Transition = React.forwardRef((props, ref) => (
  <Slide direction="up" ref={ref} {...props} />
));
Transition.displayName = 'TransitionSlide';

const styles = () => ({
  labels: {
    margin: 0,
    padding: 0,
  },
  label: {
    margin: '0 7px 7px 0',
  },
  labelInput: {
    margin: '4px 0 0 10px',
    float: 'right',
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
});

const stixCoreObjectMutationRelationsAdd = graphql`
  mutation StixCoreObjectLabelsViewRelationsAddMutation(
    $id: ID!
    $input: StixMetaRelationshipsAddInput!
  ) {
    stixCoreObjectEdit(id: $id) {
      relationsAdd(input: $input) {
        objectLabel {
          edges {
            node {
              id
              value
              color
            }
          }
        }
      }
    }
  }
`;

const stixCoreObjectMutationRelationDelete = graphql`
  mutation StixCoreObjectLabelsViewRelationDeleteMutation(
    $id: ID!
    $toId: StixRef!
    $relationship_type: String!
  ) {
    stixCoreObjectEdit(id: $id) {
      relationDelete(toId: $toId, relationship_type: $relationship_type) {
        ... on StixCoreObject {
          objectLabel {
            edges {
              node {
                id
                value
                color
              }
            }
          }
        }
      }
    }
  }
`;

const StixCoreObjectLabelsView = (props) => {
  const { classes, labels, t, marginTop } = props;
  const { me } = useContext(UserContext);
  const isLabelManager = granted(me, [SETTINGS_SETLABELS]);
  const [openAdd, setOpenAdd] = useState(false);
  const [openCreate, setOpenCreate] = useState(false);
  const [stateLabels, setStateLabels] = useState([]);
  const [labelInput, setLabelInput] = useState('');

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

  const handleCloseAdd = () => setOpenAdd(false);
  const onSubmit = (values, { setSubmitting, resetForm }) => {
    const currentLabelsIds = map((label) => label.node.id, labels.edges);
    const labelsIds = pipe(
      map((value) => value.value),
      filter((value) => !currentLabelsIds.includes(value)),
    )(values.new_labels);
    commitMutation({
      mutation: stixCoreObjectMutationRelationsAdd,
      variables: {
        id: props.id,
        input: {
          toIds: labelsIds,
          relationship_type: 'object-label',
        },
      },
      setSubmitting,
      onCompleted: () => {
        setSubmitting(false);
        resetForm();
        handleCloseAdd();
      },
    });
  };

  const handleRemoveLabel = (labelId) => {
    commitMutation({
      mutation: stixCoreObjectMutationRelationDelete,
      variables: {
        id: props.id,
        toId: labelId,
        relationship_type: 'object-label',
      },
    });
  };

  const handleOpenAdd = () => setOpenAdd(true);
  const handleOpenCreate = () => setOpenCreate(true);
  const handleCloseCreate = () => setOpenCreate(false);
  const onReset = () => {
    setOpenAdd(false);
  };

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
                  onDelete={() => handleRemoveLabel(label.id)}
                  deleteIcon={
                    <CancelOutlined
                      className={classes.deleteIcon}
                      style={{
                        color: label.color,
                      }}
                    />
                  }
                />
              </Tooltip>
            </Security>
          ),
          labelsNodes,
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
                onClick={submitForm}
                disabled={isSubmitting}
                color="secondary"
              >
                {t('Add')}
              </Button>
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

StixCoreObjectLabelsView.propTypes = {
  classes: PropTypes.object.isRequired,
  t: PropTypes.func,
  id: PropTypes.string,
  labels: PropTypes.object,
};

export default compose(inject18n, withStyles(styles))(StixCoreObjectLabelsView);
