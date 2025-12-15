import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import * as R from 'ramda';
import withStyles from '@mui/styles/withStyles';
import Dialog from '@mui/material/Dialog';
import DialogTitle from '@mui/material/DialogTitle';
import DialogContent from '@mui/material/DialogContent';
import DialogActions from '@mui/material/DialogActions';
import Button from '@common/button/Button';
import Slide from '@mui/material/Slide';
import { Add, InfoOutlined } from '@mui/icons-material';
import { createFragmentContainer, graphql } from 'react-relay';
import { Field, Form, Formik } from 'formik';
import MenuItem from '@mui/material/MenuItem';
import * as Yup from 'yup';
import Tooltip from '@mui/material/Tooltip';
import Fab from '@mui/material/Fab';
import { CONTENT_MAX_MARKINGS_HELPERTEXT, CONTENT_MAX_MARKINGS_TITLE } from '../files/FileManager';
import ObjectMarkingField from '../form/ObjectMarkingField';
import inject18n from '../../../../components/i18n';
import { commitMutation, MESSAGING$, QueryRenderer } from '../../../../relay/environment';
import { markingDefinitionsLinesSearchQuery } from '../../settings/MarkingDefinitionsQuery';
import SelectField from '../../../../components/fields/SelectField';
import Loader from '../../../../components/Loader';
import { ExportContext } from '../../../../utils/ExportContextProvider';
import { emptyFilterGroup, removeIdAndIncorrectKeysFromFilterGroupObject } from '../../../../utils/filters/filtersUtils';
import { UserContext } from '../../../../utils/hooks/useAuth';
import { fieldSpacingContainerStyle } from '../../../../utils/field';

const Transition = React.forwardRef((props, ref) => (
  <Slide direction="up" ref={ref} {...props} />
));
Transition.displayName = 'TransitionSlide';

const styles = () => ({
  createButton: {
    position: 'fixed',
    bottom: 30,
    right: 30,
    zIndex: 2000,
  },
  listIcon: {
    marginRight: 0,
  },
  item: {
    padding: '0 0 0 10px',
  },
  itemField: {
    padding: '0 15px 0 15px',
  },
});

export const StixCoreRelationshipsExportCreationMutation = graphql`
  mutation StixCoreRelationshipsExportCreationMutation(
    $input: StixCoreRelationshipsExportAskInput!
  ) {
    stixCoreRelationshipsExportAsk(input: $input) {
      id
    }
  }
`;

const exportValidation = (t_i18n) => Yup.object().shape({
  format: Yup.string().required(t_i18n('This field is required')),
});

export const scopesConn = (exportConnectors) => {
  const scopes = R.uniq(
    R.flatten(exportConnectors.map((c) => c.connector_scope)),
  );
  const connectors = scopes.map((s) => {
    const filteredConnectors = exportConnectors.filter((e) => R.includes(s, e.connector_scope));
    return filteredConnectors.map((x) => ({
      data: { name: x.name, active: x.active },
    }));
  });
  const zipped = R.zip(scopes, connectors);
  return R.fromPairs(zipped);
};

class StixCoreRelationshipsExportCreationComponent extends Component {
  constructor(props) {
    super(props);
    this.state = { open: false, selectedContentMaxMarkingsIds: [] };
  }

  handleSelectedContentMaxMarkingsChange(values) {
    this.setState({ selectedContentMaxMarkingsIds: values.map(({ value }) => value) });
  }

  handleOpen() {
    this.setState({ open: true });
  }

  handleClose() {
    this.setState({ open: false });
  }

  onSubmit(selectedIds, availableFilterKeys, values, { setSubmitting, resetForm }) {
    const { paginationOptions, exportContext } = this.props;
    const { orderBy, orderMode, filters, search } = paginationOptions;
    const contentMaxMarkings = values.contentMaxMarkings.map(({ value }) => value);
    const fileMarkings = values.fileMarkings.map(({ value }) => value);
    const finalFilters = filters ?? emptyFilterGroup;

    commitMutation({
      mutation: StixCoreRelationshipsExportCreationMutation,
      variables: {
        input: {
          format: values.format,
          exportType: 'full',
          contentMaxMarkings,
          fileMarkings,
          exportContext,
          orderMode,
          orderBy,
          filters: removeIdAndIncorrectKeysFromFilterGroupObject(finalFilters, availableFilterKeys),
          selectedIds,
          search,
        },
      },
      onCompleted: () => {
        setSubmitting(false);
        resetForm();
        if (this.props.onExportAsk) this.props.onExportAsk();
        this.handleClose();
        MESSAGING$.notifySuccess('Export successfully started');
      },
    });
  }

  render() {
    const { classes, t, data } = this.props;
    const connectorsExport = data?.connectorsForExport ?? [];
    const exportScopes = R.uniq(
      R.flatten(R.map((c) => c.connector_scope, connectorsExport)),
    );
    const exportConnsPerFormat = scopesConn(connectorsExport);

    const isExportActive = (format) => exportConnsPerFormat[format].filter((x) => x.data.active).length > 0;
    const isExportPossible = exportScopes.filter((x) => isExportActive(x)).length > 0;
    return (
      <UserContext.Consumer>
        {({ schema }) => {
          const availableFilterKeys = Array.from(schema.filterKeysSchema.get('stix-core-relationship')?.keys() ?? []).concat(['entity_type']);
          return (
            <ExportContext.Consumer>
              {({ selectedIds }) => {
                return (
                  <div>
                    <Tooltip
                      title={
                        isExportPossible
                          ? t('Generate an export')
                          : t('No export connector available to generate an export')
                      }
                      aria-label="generate-export"
                    >
                      <Fab
                        data-testid="StixCoreRelationshipsExportCreationAddButton"
                        onClick={this.handleOpen.bind(this)}
                        color="secondary"
                        aria-label="Add"
                        className={classes.createButton}
                        disabled={!isExportPossible}
                      >
                        <Add />
                      </Fab>
                    </Tooltip>
                    <Formik
                      enableReinitialize={true}
                      initialValues={{
                        format: '',
                        contentMaxMarkings: [],
                        fileMarkings: [],
                      }}
                      validationSchema={exportValidation(t)}
                      onSubmit={this.onSubmit.bind(this, selectedIds, availableFilterKeys)}
                      onReset={this.handleClose.bind(this)}
                    >
                      {({ submitForm, handleReset, isSubmitting, resetForm, setFieldValue }) => (
                        <Form>
                          <Dialog
                            data-testid="StixCoreRelationshipsExportCreationDialog"
                            slotProps={{ paper: { elevation: 1 } }}
                            open={this.state.open}
                            onClose={() => {
                              resetForm();
                              this.handleClose();
                            }}
                            fullWidth={true}
                          >
                            <DialogTitle>
                              {t('Generate an export')}
                              <Tooltip title={t('Your max shareable markings will be applied to the content max markings')}>
                                <InfoOutlined sx={{ paddingLeft: 1 }} fontSize="small" />
                              </Tooltip>
                            </DialogTitle>
                            <QueryRenderer
                              query={markingDefinitionsLinesSearchQuery}
                              variables={{ first: 200 }}
                              render={({ props }) => {
                                if (props && props.markingDefinitions) {
                                  return (
                                    <DialogContent>
                                      <Field
                                        component={SelectField}
                                        variant="standard"
                                        name="format"
                                        label={t('Export format')}
                                        fullWidth={true}
                                        containerstyle={{ width: '100%' }}
                                      >
                                        {exportScopes.map((value, i) => (
                                          <MenuItem
                                            key={i}
                                            value={value}
                                            disabled={!isExportActive(value)}
                                          >
                                            {value}
                                          </MenuItem>
                                        ))}
                                      </Field>
                                      <ObjectMarkingField
                                        name="contentMaxMarkings"
                                        label={t(CONTENT_MAX_MARKINGS_TITLE)}
                                        onChange={(_, values) => this.handleSelectedContentMaxMarkingsChange(values)}
                                        style={fieldSpacingContainerStyle}
                                        setFieldValue={setFieldValue}
                                        limitToMaxSharing
                                        helpertext={t(CONTENT_MAX_MARKINGS_HELPERTEXT)}
                                      />
                                      <ObjectMarkingField
                                        name="fileMarkings"
                                        label={t('File marking definition levels')}
                                        filterTargetIds={this.state.selectedContentMaxMarkingsIds}
                                        style={fieldSpacingContainerStyle}
                                        setFieldValue={setFieldValue}
                                      />
                                    </DialogContent>
                                  );
                                }
                                return <Loader variant="inElement" />;
                              }}
                            />
                            <DialogActions>
                              <Button variant="secondary" onClick={handleReset} disabled={isSubmitting}>
                                {t('Cancel')}
                              </Button>
                              <Button
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
              }}
            </ExportContext.Consumer>
          );
        }}
      </UserContext.Consumer>
    );
  }
}

const StixCoreRelationshipsExportCreations = createFragmentContainer(
  StixCoreRelationshipsExportCreationComponent,
  {
    data: graphql`
      fragment StixCoreRelationshipsExportCreation_data on Query {
        connectorsForExport {
          id
          name
          active
          connector_scope
          updated_at
        }
      }
    `,
  },
);

StixCoreRelationshipsExportCreations.propTypes = {
  classes: PropTypes.object.isRequired,
  t: PropTypes.func,
  data: PropTypes.object,
  exportContext: PropTypes.object,
  paginationOptions: PropTypes.object,
  onExportAsk: PropTypes.func,
};

export default R.compose(
  inject18n,
  withStyles(styles),
)(StixCoreRelationshipsExportCreations);
