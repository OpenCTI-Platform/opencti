import React, { Component } from 'react';
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
import Button from '@material-ui/core/Button';
import Slide from '@material-ui/core/Slide';
import { Add, CancelOutlined } from '@material-ui/icons';
import { Label } from 'mdi-material-ui';
import { commitMutation, fetchQuery } from '../../../../relay/environment';
import inject18n from '../../../../components/i18n';
import { labelsSearchQuery } from '../../settings/Labels';
import AutocompleteField from '../../../../components/AutocompleteField';
import LabelCreation from '../../settings/labels/LabelCreation';
import Security, { KNOWLEDGE_KNUPDATE } from '../../../../utils/Security';
import { hexToRGB } from '../../../../utils/Colors';

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
    $toId: String!
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

class StixCoreObjectLabelsView extends Component {
  constructor(props) {
    super(props);
    this.state = {
      openAdd: false,
      openCreate: false,
      labels: [],
      labelInput: '',
    };
  }

  handleOpenAdd() {
    this.setState({ openAdd: true });
  }

  handleCloseAdd() {
    this.setState({ openAdd: false });
  }

  handleOpenCreate() {
    this.setState({ openCreate: true });
  }

  handleCloseCreate() {
    this.setState({ openCreate: false });
  }

  searchLabels(event) {
    this.setState({
      labelInput: event && event.target.value !== 0 ? event.target.value : '',
    });
    fetchQuery(labelsSearchQuery, {
      search: event && event.target.value !== 0 ? event.target.value : '',
    }).then((data) => {
      const labels = pipe(
        pathOr([], ['labels', 'edges']),
        map((n) => ({
          label: n.node.value,
          value: n.node.id,
          color: n.node.color,
        })),
      )(data);
      this.setState({
        labels: union(this.state.labels, labels),
      });
    });
  }

  onSubmit(values, { setSubmitting, resetForm }) {
    const currentLabelsIds = map(
      (label) => label.node.id,
      this.props.labels.edges,
    );
    const labelsIds = pipe(
      map((value) => value.value),
      filter((value) => !currentLabelsIds.includes(value)),
    )(values.new_labels);
    commitMutation({
      mutation: stixCoreObjectMutationRelationsAdd,
      variables: {
        id: this.props.id,
        input: {
          toIds: labelsIds,
          relationship_type: 'object-label',
        },
      },
      setSubmitting,
      onCompleted: () => {
        setSubmitting(false);
        resetForm();
        this.handleCloseAdd();
      },
    });
  }

  handleRemoveLabel(labelId) {
    commitMutation({
      mutation: stixCoreObjectMutationRelationDelete,
      variables: {
        id: this.props.id,
        toId: labelId,
        relationship_type: 'object-label',
      },
    });
  }

  onReset() {
    this.handleCloseAdd();
  }

  render() {
    const { classes, labels, t } = this.props;
    const labelsNodes = pipe(
      map((n) => n.node),
      sortWith([ascend(prop('value'))]),
    )(labels.edges);
    return (
      <div>
        <Typography variant="h3" gutterBottom={true} style={{ float: 'left' }}>
          {t('Labels')}
        </Typography>
        <Security needs={[KNOWLEDGE_KNUPDATE]}>
          <IconButton
            color="secondary"
            aria-label="Label"
            onClick={this.handleOpenAdd.bind(this)}
            style={{ float: 'left', margin: '-15px 0 0 -2px' }}
          >
            <Add fontSize="small" />
          </IconButton>
        </Security>
        <div className="clearfix" />
        <div className={classes.objectLabel}>
          {map(
            (label) => (
              <Chip
                key={label.id}
                variant="outlined"
                classes={{ root: classes.label }}
                label={label.value}
                style={{
                  color: label.color,
                  borderColor: label.color,
                  backgroundColor: hexToRGB(label.color),
                }}
                onDelete={this.handleRemoveLabel.bind(this, label.id)}
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
        <Formik
          initialValues={{ new_labels: [] }}
          onSubmit={this.onSubmit.bind(this)}
          onReset={this.onReset.bind(this)}
        >
          {({
            submitForm,
            handleReset,
            isSubmitting,
            setFieldValue,
            values,
          }) => (
            <Dialog
              open={this.state.openAdd}
              TransitionComponent={Transition}
              onClose={this.handleCloseAdd.bind(this)}
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
                      label: t('Labels'),
                      onFocus: this.searchLabels.bind(this),
                    }}
                    noOptionsText={t('No available options')}
                    options={this.state.labels}
                    onInputChange={this.searchLabels.bind(this)}
                    openCreate={this.handleOpenCreate.bind(this)}
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
              <DialogActions>
                <Button
                  onClick={handleReset}
                  disabled={isSubmitting}
                  color="primary"
                >
                  {t('Close')}
                </Button>
                <Button
                  onClick={submitForm}
                  disabled={isSubmitting}
                  color="primary"
                >
                  {t('Add')}
                </Button>
              </DialogActions>
              <LabelCreation
                contextual={true}
                open={this.state.openCreate}
                inputValue={this.state.labelInput}
                handleClose={this.handleCloseCreate.bind(this)}
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
  }
}

StixCoreObjectLabelsView.propTypes = {
  classes: PropTypes.object.isRequired,
  t: PropTypes.func,
  id: PropTypes.string,
  labels: PropTypes.object,
};

export default compose(inject18n, withStyles(styles))(StixCoreObjectLabelsView);
