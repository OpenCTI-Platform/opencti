import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { Field, Form, Formik } from 'formik';
import { ConnectionHandler } from 'relay-runtime';
import * as R from 'ramda';
import {
  assoc,
  compose,
  dissoc,
  filter,
  includes,
  map,
  pipe,
  pluck,
  split,
} from 'ramda';
import * as Yup from 'yup';
import { graphql } from 'react-relay';
import withStyles from '@mui/styles/withStyles';
import Dialog from '@mui/material/Dialog';
import DialogContent from '@mui/material/DialogContent';
import DialogTitle from '@mui/material/DialogTitle';
import DialogActions from '@mui/material/DialogActions';
import Button from '@mui/material/Button';
import MenuItem from '@mui/material/MenuItem';
import Fab from '@mui/material/Fab';
import { Add } from '@mui/icons-material';
import { commitMutation, QueryRenderer } from '../../../../relay/environment';
import inject18n from '../../../../components/i18n';
import TextField from '../../../../components/TextField';
import MarkDownField from '../../../../components/MarkDownField';
import SelectField from '../../../../components/SelectField';
import CreatedByField from '../form/CreatedByField';
import ObjectMarkingField from '../form/ObjectMarkingField';
import ObjectLabelField from '../form/ObjectLabelField';
import ConfidenceField from '../form/ConfidenceField';
import {
  typesWithOpenCTIAliases,
  typesWithoutAliases,
} from '../../../../utils/Entity';
import { fieldSpacingContainerStyle } from '../../../../utils/field';
import OpenVocabField from '../form/OpenVocabField';

export const stixDomainObjectCreationAllTypesQuery = graphql`
  query StixDomainObjectCreationAllTypesQuery {
    sdoTypes: subTypes(type: "Stix-Domain-Object") {
      edges {
        node {
          id
          label
        }
      }
    }
  }
`;

const styles = (theme) => ({
  drawerPaper: {
    minHeight: '100vh',
    width: '50%',
    position: 'fixed',
    transition: theme.transitions.create('width', {
      easing: theme.transitions.easing.sharp,
      duration: theme.transitions.duration.enteringScreen,
    }),
    padding: 0,
  },
  createButton: {
    position: 'fixed',
    bottom: 30,
    right: 30,
    zIndex: 2000,
  },
  buttons: {
    marginTop: 20,
    textAlign: 'right',
  },
  button: {
    marginLeft: theme.spacing(2),
  },
  header: {
    backgroundColor: theme.palette.background.nav,
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

const stixDomainObjectCreationMutation = graphql`
  mutation StixDomainObjectCreationMutation($input: StixDomainObjectAddInput!) {
    stixDomainObjectAdd(input: $input) {
      id
      entity_type
      parent_types
      revoked
      objectLabel {
        edges {
          node {
            id
            value
            color
          }
        }
      }
      createdBy {
        ... on Identity {
          id
          name
          entity_type
        }
      }
      objectMarking {
        edges {
          node {
            id
            definition_type
            definition
            x_opencti_order
            x_opencti_color
          }
        }
      }
      ... on AttackPattern {
        name
        description
      }
      ... on Campaign {
        name
        description
      }
      ... on CourseOfAction {
        name
        description
      }
      ... on Individual {
        name
        description
      }
      ... on Organization {
        name
        description
      }
      ... on Sector {
        name
        description
      }
      ... on System {
        name
        description
      }
      ... on Indicator {
        name
        description
      }
      ... on Infrastructure {
        name
        description
      }
      ... on IntrusionSet {
        name
        description
      }
      ... on Position {
        name
        description
      }
      ... on City {
        name
        description
      }
      ... on AdministrativeArea {
        name
        description
      }
      ... on Country {
        name
        description
      }
      ... on Region {
        name
        description
      }
      ... on Malware {
        name
        description
      }
      ... on ThreatActor {
        name
        description
      }
      ... on Tool {
        name
        description
      }
      ... on Vulnerability {
        name
        description
      }
      ... on Incident {
        name
        description
      }
      ... on Event {
        name
        description
      }
      ... on Channel {
        name
        description
      }
      ... on Narrative {
        name
        description
      }
      ... on Language {
        name
      }
      ... on DataComponent {
        name
      }
      ... on DataSource {
        name
      }
      ... on Case {
        name
      }
      ... on Report {
        name
      }
      ... on Grouping {
        name
      }
    }
  }
`;

const stixDomainObjectValidation = (t) => Yup.object().shape({
  name: Yup.string().required(t('This field is required')),
  confidence: Yup.number().required(t('This field is required')),
  description: Yup.string().nullable(),
  type: Yup.string().required(t('This field is required')),
});

const sharedUpdater = (
  store,
  userId,
  paginationOptions,
  paginationKey,
  newEdge,
) => {
  const userProxy = store.get(userId);
  const conn = ConnectionHandler.getConnection(
    userProxy,
    paginationKey,
    paginationOptions,
  );
  ConnectionHandler.insertEdgeBefore(conn, newEdge);
};

class StixDomainObjectCreation extends Component {
  constructor(props) {
    super(props);
    this.state = { open: false };
  }

  handleOpen() {
    this.setState({ open: true });
  }

  handleClose() {
    this.setState({ open: false });
  }

  onSubmit(values, { setSubmitting, resetForm }) {
    let finalValues = pipe(
      assoc('confidence', parseInt(values.confidence, 10)),
      assoc('createdBy', values.createdBy?.value),
      assoc('objectMarking', pluck('value', values.objectMarking)),
      assoc('objectLabel', pluck('value', values.objectLabel)),
    )(values);
    if (finalValues.type !== 'Indicator') {
      finalValues = pipe(
        dissoc('pattern_type'),
        dissoc('pattern'),
      )(finalValues);
    }
    if (includes(finalValues.type, typesWithoutAliases)) {
      finalValues = pipe(
        dissoc('aliases'),
        dissoc('x_opencti_aliases'),
      )(finalValues);
    } else if (includes(finalValues.type, typesWithOpenCTIAliases)) {
      finalValues = pipe(
        dissoc('aliases'),
        assoc(
          'x_opencti_aliases',
          filter((n) => n.length > 0, split(',', finalValues.x_opencti_aliases)),
        ),
      )(finalValues);
    } else {
      finalValues = pipe(
        dissoc('x_opencti_aliases'),
        assoc(
          'aliases',
          filter((n) => n.length > 0, split(',', finalValues.aliases)),
        ),
      )(finalValues);
    }
    commitMutation({
      mutation: stixDomainObjectCreationMutation,
      variables: {
        input: finalValues,
      },
      updater: (store) => {
        if (!this.props.creationCallback) {
          const payload = store.getRootField('stixDomainObjectAdd');
          const newEdge = payload.setLinkedRecord(payload, 'node'); // Creation of the pagination container.
          const container = store.getRoot();
          sharedUpdater(
            store,
            container.getDataID(),
            this.props.paginationOptions,
            this.props.paginationKey || 'Pagination_stixDomainObjects',
            newEdge,
          );
        }
      },
      setSubmitting,
      onCompleted: (response) => {
        setSubmitting(false);
        resetForm();
        if (this.props.creationCallback) {
          this.props.creationCallback(response);
          this.props.handleClose();
        } else {
          this.handleClose();
        }
      },
    });
  }

  onResetContextual() {
    if (this.props.speeddial) {
      this.props.handleClose();
    } else {
      this.handleClose();
    }
  }

  renderEntityTypesList() {
    const { t, stixDomainObjectTypes } = this.props;
    return (
      <QueryRenderer
        query={stixDomainObjectCreationAllTypesQuery}
        render={({ props: data }) => {
          if (data && data.sdoTypes) {
            let result = [];
            result = [
              ...R.pipe(
                R.pathOr([], ['sdoTypes', 'edges']),
                R.map((n) => ({
                  label: t(`entity_${n.node.label}`),
                  value: n.node.label,
                  type: n.node.label,
                })),
              )(data),
              ...result,
            ];
            const entitiesTypes = R.sortWith(
              [R.ascend(R.prop('label'))],
              result,
            );
            const availableEntityTypes = R.filter((n) => {
              if (
                !stixDomainObjectTypes
                || stixDomainObjectTypes.length === 0
                || stixDomainObjectTypes.includes('Stix-Domain-Object')
              ) {
                return true;
              }
              if (
                stixDomainObjectTypes.includes('Identity')
                && [
                  'Sector',
                  'Organization',
                  'Individual',
                  'System',
                  'Event',
                ].includes(n.value)
              ) {
                return true;
              }
              if (
                stixDomainObjectTypes.includes('Location')
                && ['Region', 'Country', 'City', 'Location'].includes(n.value)
              ) {
                return true;
              }
              return !!stixDomainObjectTypes.includes(n.value);
            }, entitiesTypes);
            return (
              <Field
                component={SelectField}
                variant="standard"
                name="type"
                label={t('Entity type')}
                fullWidth={true}
                containerstyle={{ width: '100%' }}
              >
                {availableEntityTypes.map((type) => (
                  <MenuItem key={type.value} value={type.value}>
                    {type.label}
                  </MenuItem>
                ))}
              </Field>
            );
          }
          return <div />;
        }}
      />
    );
  }

  renderContextual() {
    const {
      t,
      classes,
      inputValue,
      display,
      speeddial,
      defaultCreatedBy,
      defaultMarkingDefinitions,
      confidence,
      stixCoreObjectTypes,
    } = this.props;
    const initialValues = {
      type: (stixCoreObjectTypes ?? []).at(0),
      name: inputValue,
      confidence: confidence || 15,
      description: '',
      aliases: '',
      x_opencti_aliases: '',
      pattern_type: '',
      pattern: '',
      createdBy: defaultCreatedBy
        ? {
          label: defaultCreatedBy.name,
          value: defaultCreatedBy.id,
          type: defaultCreatedBy.entity_type,
        }
        : '',
      objectLabel: [],
      objectMarking: defaultMarkingDefinitions
        ? map(
          (n) => ({
            label: n.definition,
            value: n.id,
            color: n.x_opencti_color,
          }),
          defaultMarkingDefinitions,
        )
        : [],
    };
    return (
      <div style={{ display: display ? 'block' : 'none' }}>
        {!speeddial && (
          <Fab
            onClick={this.handleOpen.bind(this)}
            color="secondary"
            aria-label="Add"
            className={classes.createButton}
          >
            <Add />
          </Fab>
        )}
        <Formik
          enableReinitialize={true}
          initialValues={initialValues}
          validationSchema={stixDomainObjectValidation(t)}
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
            <Form>
              <Dialog
                PaperProps={{ elevation: 1 }}
                open={speeddial ? this.props.open : this.state.open}
                onClose={
                  speeddial
                    ? this.props.handleClose.bind(this)
                    : this.handleClose.bind(this)
                }
                fullWidth={true}
              >
                <DialogTitle>{t('Create an entity')}</DialogTitle>
                <DialogContent>
                  {this.renderEntityTypesList()}
                  <Field
                    component={TextField}
                    variant="standard"
                    name="name"
                    label={t('Name')}
                    fullWidth={true}
                    style={{ marginTop: 20 }}
                    detectDuplicate={stixCoreObjectTypes || []}
                  />
                  {!includes(values.type, typesWithoutAliases) && (
                    <Field
                      component={TextField}
                      variant="standard"
                      name={
                        includes(values.type, typesWithOpenCTIAliases)
                          ? 'x_opencti_aliases'
                          : 'aliases'
                      }
                      label={t('Aliases separated by commas')}
                      fullWidth={true}
                      style={{ marginTop: 20 }}
                    />
                  )}
                  {values.type === 'Indicator' && (
                    <div>
                      <OpenVocabField
                        label={t('Pattern type')}
                        type="pattern_type_ov"
                        name="pattern_type"
                        onChange={(name, value) => setFieldValue(name, value)}
                        containerStyle={fieldSpacingContainerStyle}
                        multiple={false}
                      />
                      <Field
                        component={TextField}
                        variant="standard"
                        name="pattern"
                        label={t('Pattern')}
                        fullWidth={true}
                        multiline={true}
                        rows="4"
                        style={{ marginTop: 20 }}
                        detectDuplicate={['Indicator']}
                      />
                    </div>
                  )}
                  <ConfidenceField
                    name="confidence"
                    label={t('Confidence')}
                    fullWidth={true}
                    containerStyle={fieldSpacingContainerStyle}
                  />
                  {values.type === 'Grouping' && (
                    <div>
                      <OpenVocabField
                        label={t('Context')}
                        type="grouping-context-ov"
                        name="context"
                        onChange={(name, value) => setFieldValue(name, value)}
                        containerStyle={fieldSpacingContainerStyle}
                        multiple={false}
                      />
                    </div>
                  )}
                  <Field
                    component={MarkDownField}
                    name="description"
                    label={t('Description')}
                    fullWidth={true}
                    multiline={true}
                    rows="4"
                    style={{ marginTop: 20 }}
                  />
                  <CreatedByField
                    name="createdBy"
                    style={{ marginTop: 20, width: '100%' }}
                    setFieldValue={setFieldValue}
                    defaultCreatedBy={defaultCreatedBy}
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
                    defaultMarkingDefinitions={defaultMarkingDefinitions}
                  />
                </DialogContent>
                <DialogActions>
                  <Button onClick={handleReset} disabled={isSubmitting}>
                    {t('Cancel')}
                  </Button>
                  <Button
                    color="secondary"
                    onClick={submitForm}
                    disabled={isSubmitting}
                  >
                    {t('Create')}
                  </Button>
                </DialogActions>
              </Dialog>
            </Form>
          )}
        </Formik>
      </div>
    );
  }

  render() {
    return this.renderContextual();
  }
}

StixDomainObjectCreation.propTypes = {
  paginationKey: PropTypes.string,
  paginationOptions: PropTypes.object,
  stixDomainObjectTypes: PropTypes.array,
  classes: PropTypes.object,
  theme: PropTypes.object,
  t: PropTypes.func,
  speeddial: PropTypes.bool,
  handleClose: PropTypes.func,
  creationCallback: PropTypes.func,
  display: PropTypes.bool,
  open: PropTypes.bool,
  inputValue: PropTypes.string,
  defaultCreatedBy: PropTypes.object,
  defaultMarkingDefinitions: PropTypes.array,
  confidence: PropTypes.number,
};

export default compose(
  inject18n,
  withStyles(styles, { withTheme: true }),
)(StixDomainObjectCreation);
