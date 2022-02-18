/* eslint-disable no-underscore-dangle */
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
import graphql from 'babel-plugin-relay/macro';
import { withStyles } from '@material-ui/core/styles';
import Typography from '@material-ui/core/Typography';
import Chip from '@material-ui/core/Chip';
import IconButton from '@material-ui/core/IconButton';
import Dialog from '@material-ui/core/Dialog';
import DialogTitle from '@material-ui/core/DialogTitle';
import DialogContent from '@material-ui/core/DialogContent';
import DialogActions from '@material-ui/core/DialogActions';
import { commitMutation as CM } from 'react-relay';
import MenuItem from '@material-ui/core/MenuItem';
import Button from '@material-ui/core/Button';
import { Add, CancelOutlined } from '@material-ui/icons';
import Tooltip from '@material-ui/core/Tooltip';
import { Label, Information } from 'mdi-material-ui';
import environmentDarkLight, { fetchDarklightQuery } from '../../../../relay/environmentDarkLight';
import { commitMutation, fetchQuery } from '../../../../relay/environment';
import inject18n from '../../../../components/i18n';
import { cyioLabelsQuery } from '../../settings/CyioLabelsQuery';
import SelectField from '../../../../components/SelectField';
import AutocompleteField from '../../../../components/AutocompleteField';
import LabelCreation from '../../settings/labels/LabelCreation';
import {
  granted,
  // KNOWLEDGE_KNUPDATE,
  SETTINGS_SETLABELS,
  UserContext,
} from '../../../../utils/Security';
import { hexToRGB } from '../../../../utils/Colors';

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

const cyioCoreObjectMutationRelationsAdd = graphql`
  mutation CyioCoreObjectLabelsViewRelationsAddMutation(
    $fieldName: String!
    $fromId: ID!
    $toId: ID!
    $from_type: String
    $to_type: String!
  ) {
    addReference(input: {field_name: $fieldName, from_id: $fromId, to_id: $toId, from_type: $from_type, to_type: $to_type})
  }
`;

const cyioCoreObjectMutationRelationDelete = graphql`
  mutation CyioCoreObjectLabelsViewRelationDeleteMutation(
    $fieldName: String!
    $fromId: ID!
    $toId: ID!
    $from_type: String
    $to_type: String!
  ) {
    removeReference(input:  {field_name: $fieldName, from_id: $fromId, to_id: $toId, from_type: $from_type, to_type: $to_type})
  }
`;

const CyioCoreObjectLabelsView = (props) => {
  const {
    classes, labels, t, marginTop, id, typename,
  } = props;
  const { me } = useContext(UserContext);
  const isLabelManager = granted(me, [SETTINGS_SETLABELS]);
  const [openAdd, setOpenAdd] = useState(false);
  const [openCreate, setOpenCreate] = useState(false);
  const [stateLabels, setStateLabels] = useState([]);
  const [labelInput, setLabelInput] = useState('');

  const searchLabels = (event) => {
    setLabelInput(event && event.target.value !== 0 ? event.target.value : '');
    fetchDarklightQuery(cyioLabelsQuery, {
      search: event && event.target.value !== 0 ? event.target.value : '',
    })
      .toPromise()
      .then((data) => {
        const transformLabels = pipe(
          pathOr([], ['cyioLabels', 'edges']),
          map((n) => ({
            label: n.node.name,
            value: n.node.id,
            color: n.node.color,
          })),
        )(data);
        setStateLabels(union(stateLabels, transformLabels));
      });
  };

  const handleCloseAdd = () => setOpenAdd(false);
  const onSubmit = (values, { setSubmitting, resetForm }) => {
    const labelsData = pipe(
      map((n) => ({
        typename: n.__typename,
        entityType: n.entity_type,
      })),
    )(labels);
    const labelsValues = pipe(
      pathOr([], ['new_labels']),
      map((n) => ({
        id: n.value,
      })),
    )(values);
    labelsValues.map((label, i) => (
      CM(environmentDarkLight, {
        mutation: cyioCoreObjectMutationRelationsAdd,
        variables: {
          toId: label.id,
          fromId: id,
          fieldName: 'labels',
          from_type: typename,
          to_type: 'CyioLabel',
          // to_type: labelsData[i].typename,
        },
        setSubmitting,
        onCompleted: (response) => {
          setSubmitting(false);
          resetForm();
          handleCloseAdd();
        },
        onError: (err) => console.log('cyioCoreObjectLabelsError', err),
      })
    ));
    // commitMutation({
    //   mutation: cyioCoreObjectMutationRelationsAdd,
    //   variables: {
    //     input: {
    //       toId: id,
    //       fromId: labelsValues[0].id,
    //       fieldName: 'labels',
    //     },
    //   },
    //   setSubmitting,
    //   onCompleted: () => {
    //     setSubmitting(false);
    //     resetForm();
    //     handleCloseAdd();
    //   },
    //   onError: (error) => console.log('cyioCoreObjectError', error),
    // });
  };

  const handleRemoveLabel = (labelId, fromType) => {
    CM(environmentDarkLight, {
      mutation: cyioCoreObjectMutationRelationDelete,
      variables: {
        toId: labelId,
        fromId: id,
        fieldName: 'labels',
        from_type: typename,
        to_type: fromType,
      },
    });
  };

  const handleOpenAdd = () => setOpenAdd(true);
  const handleOpenCreate = () => setOpenCreate(true);
  const handleCloseCreate = () => setOpenCreate(false);
  const onReset = () => {
    setOpenAdd(false);
  };

  // const labelsNodes = pipe(
  //   labelsValues.((n) => n.node),
  //   sortWith([ascend(prop('value'))]),
  // )(labels.edges);
  const labelsNodes = pipe(
    map((n) => n),
    sortWith([ascend(prop('name'))]),
  )(labels);
  return (
    <div style={{ marginTop: marginTop || 0 }}>
      <Typography variant="h3" gutterBottom={true} style={{ float: 'left' }}>
        {t('Labels')}
      </Typography>
      <div style={{ float: 'left', margin: '-1px 0 0 4px' }}>
        <Tooltip
          title={t(
            'Label',
          )}
        >
          <Information fontSize="inherit" color="disabled" />
        </Tooltip>
      </div>
      {/* <Security needs={[KNOWLEDGE_KNUPDATE]}> */}
      <IconButton
        color="secondary"
        aria-label="Label"
        size="small"
        onClick={handleOpenAdd}
        style={{ float: 'left', margin: '-8px 0 0 -2px' }}
      >
        <Add fontSize="small" />
      </IconButton>
      {/* </Security> */}
      <div className="clearfix" />
      {labels ? (
        <div className={classes.objectLabel}>
          {map(
            (label) => (
              <Chip
                key={label.id}
                variant="outlined"
                classes={{ root: classes.label }}
                label={label.name}
                style={{
                  color: label.color,
                  borderColor: label.color,
                  backgroundColor: hexToRGB(label.color),
                }}
                onDelete={() => handleRemoveLabel(label.id, label.__typename)}
                deleteIcon={
                  <CancelOutlined
                    className={classes.deleteIcon}
                    style={{
                      color: label.color,
                    }}
                  />
                }
              />
            ),
            labelsNodes,
          )}
        </div>
      ) : (
        <Field
          component={SelectField}
          variant='outlined'
          size='small'
          name="labels"
          fullWidth={true}
          containerstyle={{ width: '50%' }}
        >
          <MenuItem key="activist" value="activist">
            {t('activist')}
          </MenuItem>
          <MenuItem key="competitor" value="competitor">
            {t('competitor')}
          </MenuItem>
        </Field>
      )}
      <Formik
        initialValues={{ new_labels: [] }}
        onSubmit={onSubmit}
        onReset={onReset}
      >
        {({
          submitForm, handleReset, isSubmitting, setFieldValue, values,
        }) => (
          <Dialog
            open={openAdd}
            onClose={handleCloseAdd}
            fullWidth={true}
          >
            <DialogTitle>{t('Add Labels')}</DialogTitle>
            <div style={{ display: 'flex', padding: '20px 20px 20px 0' }}>
              <DialogContent style={{ overflowY: 'hidden', width: '70%', paddingTop: '0' }}>
                <Form>
                  <Field
                    component={AutocompleteField}
                    name="new_labels"
                    multiple={true}
                    freeSolo={false}
                    textfieldprops={{
                      label: t('Labels'),
                      onFocus: searchLabels,
                    }}
                    noOptionsText={t('No available options')}
                    options={stateLabels}
                    onInputChange={searchLabels}
                    openCreate={handleOpenCreate}
                    renderOption={(option) => (
                      <React.Fragment>
                        <div
                          className={classes.icon}
                          style={{ color: option.color }}
                        >
                          <Label />
                        </div>
                        <div className={classes.text}>{option.label}</div>
                      </React.Fragment>
                    )}
                    classes={{ clearIndicator: classes.autoCompleteIndicator }}
                  />
                </Form>
              </DialogContent>
              <DialogActions style={{ width: '30%', padding: '0' }}>
                <Button
                  onClick={handleReset}
                  disabled={isSubmitting}
                  color="primary"
                  variant='outlined'
                >
                  {t('Close')}
                </Button>
                <Button
                  onClick={submitForm}
                  disabled={isSubmitting}
                  color="primary"
                  variant="contained"
                >
                  {t('Add')}
                </Button>
              </DialogActions>
            </div>
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
                      label: data.createCyioLabel.name,
                      value: data.createCyioLabel.id,
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

CyioCoreObjectLabelsView.propTypes = {
  classes: PropTypes.object.isRequired,
  typename: PropTypes.string,
  t: PropTypes.func,
  id: PropTypes.string,
  labels: PropTypes.object,
};

export default compose(inject18n, withStyles(styles))(CyioCoreObjectLabelsView);
