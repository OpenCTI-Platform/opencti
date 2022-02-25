/* eslint-disable */
/* refactor */
import React, { Component, useContext } from 'react';
import * as PropTypes from 'prop-types';
import { Formik, Form, Field } from 'formik';
// import { ConnectionHandler } from 'relay-runtime';
import {
  compose, union, map, pathOr, pipe, dissoc,
} from 'ramda';
import * as Yup from 'yup';
import graphql from 'babel-plugin-relay/macro';
import { withStyles } from '@material-ui/core/styles';
import Drawer from '@material-ui/core/Drawer';
import Dialog from '@material-ui/core/Dialog';
import Grid from '@material-ui/core/Grid';
import Typography from '@material-ui/core/Typography';
import Button from '@material-ui/core/Button';
import IconButton from '@material-ui/core/IconButton';
import Badge from '@material-ui/core/Badge';
import Avatar from '@material-ui/core/Avatar';
import Fab from '@material-ui/core/Fab';
import { Add, Close } from '@material-ui/icons';
import { commitMutation as CM } from 'react-relay';
import { cyioLabelsQuery } from '../../settings/CyioLabelsQuery';
import { commitMutation, QueryRenderer } from '../../../../relay/environment';
import environmentDarkLight, { fetchDarklightQuery } from '../../../../relay/environmentDarkLight';
// import { commitMutation } from '../../../../relay/environment';
import inject18n from '../../../../components/i18n';
import ObjectMarkingField from '../../common/form/ObjectMarkingField';
import CreatedByField from '../../common/form/CreatedByField';
import ObjectLabelField from '../../common/form/ObjectLabelField';
import MarkDownField from '../../../../components/MarkDownField';
import ConfidenceField from '../../common/form/ConfidenceField';
import { Label, Information } from 'mdi-material-ui';
import { dayStartDate } from '../../../../utils/Time';
import DatePickerField from '../../../../components/DatePickerField';
import TextField from '../../../../components/TextField';
import { UserContext } from '../../../../utils/Security';
import AutocompleteField from '../../../../components/AutocompleteField';
import LabelCreation from '../../settings/labels/LabelCreation';
const styles = (theme) => ({
  drawerPaper: {
    minHeight: '452px',
    width: '750px',
    maxWidth: '750px',
    backgroundColor: theme.palette.navAlt.background,
    transition: theme.transitions.create('width', {
      easing: theme.transitions.easing.sharp,
      duration: theme.transitions.duration.enteringScreen,
    }),
    padding: '25px 24px 32px 24px',
  },
  createButton: {
    position: 'fixed',
    bottom: 30,
    right: 30,
  },
  title: {
    float: 'left',
  },
  icon: {
    paddingTop: 4,
    display: 'inline-block',
  },
  createButtonContextual: {
    marginTop: -15,
    // bottom: 30,
    // right: 30,
  },
  buttons: {
    marginTop: 20,
    textAlign: 'right',
  },
  button: {
    marginLeft: theme.spacing(2),
  },
  header: {
    backgroundColor: theme.palette.navAlt.backgroundHeader,
    color: theme.palette.navAlt.backgroundHeaderText,
    padding: '20px 20px 20px 60px',
  },
  closeButton: {
    position: 'absolute',
    top: 12,
    left: 5,
    color: 'inherit',
  },
  importButton: {
    position: 'absolute',
    top: 15,
    right: 20,
  },
  container: {
    padding: '10px 20px 20px 20px',
  },
});

export const cyioNoteCreationMutation = graphql`
  mutation CyioNoteCreationMutation($input: CyioNoteAddInput!) {
    createCyioNote(input: $input) {
      __typename
      id
      entity_type
      labels {
        __typename
        id
        name
        color
        entity_type
        description
      }
      abstract
      content
      authors
      # ...NoteLine_node
    }
  }
`;

const cyioNoteValidation = (t) => Yup.object().shape({
  confidence: Yup.number(),
  // created: Yup.date()
  //   .typeError(t('The value must be a date (YYYY-MM-DD)'))
  //   .required(t('This field is required')),
  attribute_abstract: Yup.string(),
  content: Yup.string().required(t('This field is required')),
});

// const sharedUpdater = (store, userId, paginationOptions, newEdge) => {
//   const userProxy = store.get(userId);
//   const conn = ConnectionHandler.getConnection(
//     userProxy,
//     'Pagination_notes',
//     paginationOptions,
//   );
//   ConnectionHandler.insertEdgeBefore(conn, newEdge);
// };

class CyioNoteCreation extends Component {
  static contextType = UserContext;
  constructor(props) {
    super(props);
    this.state = {
      open: false,
      stateLabels: [],
      labelInput: '',
      openCreate: false,
    };
  }

  // componentDidMount() {
  //   const { me } = this.context

  //   console.log('sdasdasdascdcd', me); // { name: 'Tania', loggedIn: true }
  // }

  handleOpen() {
    this.setState({ open: true });
  }

  handleLabelOpen() {
    this.setState({ openCreate: true });
  }

  handleLabelClose() {
    this.setState({ openCreate: false });
  }

  handleClose() {
    this.setState({ open: false });
  }

  searchLabels = (event) => {
    this.setState({
      labelInput: event && event.target.value !== 0 ? event.target.value : '',
    });
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
        this.setState({
          stateLabels: union(this.state.stateLabels, transformLabels),
        });
      });
  };

  onSubmit(values, { setSubmitting, resetForm }) {
    // const adaptedValues = evolve(
    //   {
    //     createdBy: path(['value']),
    //     objectMarking: pluck('value'),
    //     objectLabel: pluck('value'),
    //   },
    //   values,
    // );
    const finalValues = pipe(
      dissoc('labels'),
    )(values);
    CM(environmentDarkLight, {
      mutation: cyioNoteCreationMutation,
      variables: {
        input: finalValues,
      },
      setSubmitting,
      onCompleted: (response) => {
        setSubmitting(false);
        resetForm();
        this.handleClose();
        if (this.props.onCreate) {
          this.props.onCreate(response.createCyioNote, true);
        }
        this.props.onExpand();
      },
      onError: (err) => console.log('NoteCreationDarkLightMutationError', err),
    });
    // commitMutation({
    //   mutation: cyioNoteCreationMutation,
    //   variables: {
    //     input: finalValues,
    //   },
    //   updater: (store) => {
    //     const payload = store.getRootField('noteAdd');
    //     const newEdge = payload.setLinkedRecord(payload, 'node');
    // Creation of the pagination container.
    //     const container = store.getRoot();
    //     sharedUpdater(
    //       store,
    //       container.getDataID(),
    //       this.props.paginationOptions,
    //       newEdge,
    //     );
    //   },
    //   setSubmitting,
    //   onCompleted: () => {
    //     setSubmitting(false);
    //     resetForm();
    //     this.handleClose();
    //   },
    // });
  }

  onResetClassic() {
    this.handleClose();
  }

  onResetContextual() {
    this.handleClose();
  }

  renderClassic() {
    const { t, classes } = this.props;
    return (
      <div>
        <Fab
          onClick={this.handleOpen.bind(this)}
          color="secondary"
          aria-label="Add"
          className={classes.createButton}
        >
          <Add />
        </Fab>
        <Drawer
          open={this.state.open}
          anchor="right"
          classes={{ paper: classes.drawerPaper }}
          onClose={this.handleClose.bind(this)}
        >
          <div className={classes.header}>
            <IconButton
              aria-label="Close"
              className={classes.closeButton}
              onClick={this.handleClose.bind(this)}
            >
              <Close fontSize="small" />
            </IconButton>
            <Typography variant="h6">{t('Create a note')}</Typography>
          </div>
          <div className={classes.container}>
            <Formik
              initialValues={{
                created: dayStartDate(),
                attribute_abstract: '',
                content: '',
                confidence: 15,
                createdBy: '',
                objectMarking: [],
                objectLabel: [],
              }}
              validationSchema={cyioNoteValidation(t)}
              onSubmit={this.onSubmit.bind(this)}
              onReset={this.onResetClassic.bind(this)}
            >
              {({
                submitForm,
                handleReset,
                isSubmitting,
                setFieldValue,
                values,
              }) => (
                <Form style={{ margin: '20px 0 20px 0' }}>
                  <Field
                    component={DatePickerField}
                    name="created"
                    label={t('Date')}
                    invalidDateMessage={t(
                      'The value must be a date (YYYY-MM-DD)',
                    )}
                    fullWidth={true}
                    style={{ marginTop: 20 }}
                  />
                  <Field
                    component={TextField}
                    name="attribute_abstract"
                    label={t('Abstract')}
                    fullWidth={true}
                  />
                  <Field
                    component={MarkDownField}
                    name="content"
                    label={t('Content')}
                    fullWidth={true}
                    multiline={true}
                    rows="4"
                    style={{ marginTop: 20 }}
                  />
                  <ConfidenceField
                    name="confidence"
                    label={t('Confidence')}
                    fullWidth={true}
                    containerstyle={{ width: '100%', marginTop: 20 }}
                  />
                  <CreatedByField
                    name="createdBy"
                    style={{ marginTop: 20, width: '100%' }}
                    setFieldValue={setFieldValue}
                  />
                  <ObjectLabelField
                    name="objectLabel"
                    style={{ marginTop: 20, width: '100%' }}
                    setFieldValue={setFieldValue}
                    values={values.objectLabel}
                  />
                  <ObjectMarkingField
                    name="objectMarking"
                    style={{ marginTop: 20, width: '100%' }}
                  />
                  <div className={classes.buttons}>
                    <Button
                      variant="contained"
                      onClick={handleReset}
                      disabled={isSubmitting}
                      classes={{ root: classes.button }}
                    >
                      {t('Cancel')}
                    </Button>
                    <Button
                      variant="contained"
                      color="primary"
                      onClick={submitForm}
                      disabled={isSubmitting}
                      classes={{ root: classes.button }}
                    >
                      {t('Create')}
                    </Button>
                  </div>
                </Form>
              )}
            </Formik>
          </div>
        </Drawer>
      </div>
    );
  }

  renderContextual() {
    const {
      t,
      classes,
      inputValue,
      display,
    } = this.props;
    const { me } = this.context;
    return (
      <div style={{ display: display ? 'block' : 'none' }}>
        <IconButton
          aria-label="Add"
          edge="end"
          onClick={this.handleOpen.bind(this)}
          color="primary"
          className={classes.createButtonContextual}
        >
          <Add fontSize="small" />
        </IconButton>
        <Dialog fullWidth={true} maxWidth='md' open={this.state.open} onClose={this.handleClose.bind(this)}>
          <Formik
            enableReinitialize={true}
            initialValues={{
              abstract: '',
              content: '',
              authors: [],
              labels: [],
            }}
            validationSchema={cyioNoteValidation(t)}
            onSubmit={this.onSubmit.bind(this)}
            onReset={this.onResetContextual.bind(this)}
          >
            {({
              submitForm,
              handleReset,
              isSubmitting,
              setFieldValue,
              values,
            }) => (
              <Form style={{ padding: '24px' }}>
                <div>
                  <Typography variant="h6" classes={{ root: classes.title }}>
                    {t('Note')}
                  </Typography>
                </div>
                <Grid
                  container={true}
                  spacing={3}
                  classes={{ container: classes.gridContainer }}
                >
                  <Grid item={true} xs={12}>
                    <Typography
                      variant="h3"
                      color="textSecondary"
                      gutterBottom={true}
                      style={{ float: 'left' }}
                    >
                      {t('Abstract')}
                    </Typography>
                    <Field
                      component={TextField}
                      name="abstract"
                      // label={t('Abstract')}
                      fullWidth={true}
                    />
                  </Grid>
                  <Grid item={true} xs={12}>
                    <Field
                      component={MarkDownField}
                      name="content"
                      fullWidth={true}
                      multiline={true}
                      rows="4"
                      style={{ marginTop: 20 }}
                    />
                  </Grid>
                  <Grid item={true} xs={6}>
                    <Field
                      component={AutocompleteField}
                      name="labels"
                      multiple={true}
                      freeSolo={true}
                      textfieldprops={{
                        label: t('Labels'),
                        onFocus: this.searchLabels.bind(this),
                      }}
                      noOptionsText={t('No available options')}
                      options={this.state.stateLabels}
                      onInputChange={this.searchLabels.bind(this)}
                      openCreate={this.handleLabelOpen.bind(this)}
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
                    <LabelCreation
                      contextual={true}
                      open={this.state.openCreate}
                      inputValue={this.state.labelInput}
                      handleClose={this.handleLabelClose.bind(this)}
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
                  </Grid>
                  <Grid style={{
                    marginLeft: 'auto',
                    display: 'grid',
                    gridTemplateColumns: '48.9% 1fr',
                    padding: '12px 12px 0 12px',
                  }}
                    container={true}>
                    <div>
                      <Typography
                        variant="h3"
                        color="textSecondary"
                        gutterBottom={true}
                        style={{ float: 'left' }}
                      >
                        {t('Author')}
                      </Typography>
                      <div className="clearfix" />
                      <Grid container={true} spacing={2}>
                        <Grid item={true} xs={12}>
                          <Field
                            component={TextField}
                            name="authors"
                            // label={t('Abstract')}
                            fullWidth={true}
                          />
                        </Grid>
                        {/* <Grid item={true} xs={6}>
                          <Field
                            component={TextField}
                            name="author"
                            // label={t('Abstract')}
                            fullWidth={true}
                          />
                        </Grid> */}
                      </Grid>
                    </div>
                    <div className={classes.buttons}>
                      <Button
                        variant="outlined"
                        onClick={handleReset}
                        classes={{ root: classes.button }}
                      >
                        {t('Cancel')}
                      </Button>
                      <Button
                        variant="contained"
                        color="primary"
                        onClick={submitForm}
                        disabled={isSubmitting}
                        classes={{ root: classes.button }}
                      >
                        {t('Create')}
                      </Button>
                    </div>
                  </Grid>
                </Grid>
              </Form>
            )}
          </Formik>
        </Dialog>
      </div>
    );
  }

  render() {
    const { contextual } = this.props;
    if (contextual) {
      return this.renderContextual();
    }
    return this.renderClassic();
  }
}

CyioNoteCreation.propTypes = {
  paginationOptions: PropTypes.object,
  classes: PropTypes.object,
  theme: PropTypes.object,
  t: PropTypes.func,
  contextual: PropTypes.bool,
  display: PropTypes.bool,
  inputValue: PropTypes.string,
  onCreate: PropTypes.func,
  onExpand: PropTypes.func,
};

export default compose(
  inject18n,
  withStyles(styles, { withTheme: true }),
)(CyioNoteCreation);
