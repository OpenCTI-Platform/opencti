import Button from '@common/button/Button';
import Dialog from '@common/dialog/Dialog';
import { Add, InfoOutlined } from '@mui/icons-material';
import { Stack } from '@mui/material';
import DialogActions from '@mui/material/DialogActions';
import Fab from '@mui/material/Fab';
import MenuItem from '@mui/material/MenuItem';
import Slide from '@mui/material/Slide';
import Tooltip from '@mui/material/Tooltip';
import withStyles from '@mui/styles/withStyles';
import { Field, Form, Formik } from 'formik';
import * as PropTypes from 'prop-types';
import { filter, flatten, fromPairs, includes, map, propOr, uniq, zip } from 'ramda';
import React, { useState } from 'react';
import { createFragmentContainer, graphql } from 'react-relay';
import * as Yup from 'yup';
import SelectField from '../../../../components/fields/SelectField';
import { useFormatter } from '../../../../components/i18n';
import Loader from '../../../../components/Loader';
import { commitMutation, MESSAGING$, QueryRenderer } from '../../../../relay/environment';
import { ExportContext } from '../../../../utils/ExportContextProvider';
import { fieldSpacingContainerStyle } from '../../../../utils/field';
import { CONTENT_MAX_MARKINGS_HELPERTEXT, CONTENT_MAX_MARKINGS_TITLE } from '../../common/files/FileManager';
import ObjectMarkingField from '../../common/form/ObjectMarkingField';
import { markingDefinitionsLinesSearchQuery } from '../../settings/MarkingDefinitionsQuery';

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

export const StixCyberObservablesExportCreationMutation = graphql`
  mutation StixCyberObservablesExportCreationMutation($input: StixCyberObservablesExportAskInput!) {
    stixCyberObservablesExportAsk(input: $input) {
      id
    }
  }
`;

const exportValidation = (t_i18n) => Yup.object().shape({
  format: Yup.string().required(t_i18n('This field is required')),
  type: Yup.string().trim().required(t_i18n('This field is required')),
});

export const scopesConn = (exportConnectors) => {
  const scopes = uniq(flatten(map((c) => c.connector_scope, exportConnectors)));
  const connectors = map((s) => {
    const filteredConnectors = filter(
      (e) => includes(s, e.connector_scope),
      exportConnectors,
    );
    return map(
      (x) => ({ data: { name: x.name, active: x.active } }),
      filteredConnectors,
    );
  }, scopes);
  const zipped = zip(scopes, connectors);
  return fromPairs(zipped);
};

const StixCyberObservablesExportCreationComponent = (props) => {
  const { t_i18n } = useFormatter();
  const [open, setOpen] = useState(false);
  const [selectedContentMaxMarkingsIds, setSelectedContentMaxMarkingsIds] = useState([]);
  const handleSelectedContentMaxMarkingsChange = (values) => {
    setSelectedContentMaxMarkingsIds(values.map(({ value }) => value));
  };

  const handleOpen = () => {
    setOpen(true);
  };

  const handleClose = () => {
    setOpen(false);
  };

  const onSubmit = (selectedIds, values, { setSubmitting, resetForm }) => {
    const { paginationOptions, exportContext } = props;
    const { orderBy, orderMode, filters, search } = paginationOptions;
    const contentMaxMarkings = values.contentMaxMarkings.map(({ value }) => value);
    const fileMarkings = values.fileMarkings.map(({ value }) => value);
    const updatedExportContext = { ...exportContext };
    // Only forward visible_columns for a "Current view" CSV export. The column
    // selector is hidden for other formats, so clear it otherwise (including
    // after the format is switched away from CSV) to avoid sending a stale
    // hidden-field value to the export connector.
    if (values.columns !== 'view' || values.format !== 'text/csv') {
      updatedExportContext.visible_columns = undefined;
    }

    commitMutation({
      mutation: StixCyberObservablesExportCreationMutation,
      variables: {
        input: {
          format: values.format,
          exportType: values.type,
          fileMarkings,
          contentMaxMarkings,
          exportContext: updatedExportContext,
          filters,
          orderBy,
          orderMode,
          selectedIds,
          search,
        },
      },
      onCompleted: () => {
        setSubmitting(false);
        resetForm();
        if (props.onExportAsk) props.onExportAsk();
        handleClose();
        MESSAGING$.notifySuccess('Export successfully started');
      },
    });
  };

  const { classes, data } = props;
  const connectorsExport = propOr([], 'connectorsForExport', data);
  const exportScopes = uniq(
    flatten(map((c) => c.connector_scope, connectorsExport)),
  );
  const exportConnsPerFormat = scopesConn(connectorsExport);
  const isExportActive = (format) => filter((x) => x.data.active, exportConnsPerFormat[format]).length > 0;
  const isExportPossible = filter((x) => isExportActive(x), exportScopes).length > 0;
  const visibleColumnExportEnabledFormats = ['text/csv'];
  return (
    <ExportContext.Consumer>
      {({ selectedIds }) => {
        return (
          <>
            <Tooltip
              title={
                isExportPossible
                  ? t_i18n('Generate an export')
                  : t_i18n('No export connector available to generate an export')
              }
              aria-label="generate-export"
            >
              <Fab
                onClick={handleOpen}
                color="primary"
                aria-label="Add"
                className={classes.createButton}
                disabled={!isExportPossible}
                data-testid="StixCyberObservablesExportCreationAddButton"
              >
                <Add />
              </Fab>
            </Tooltip>
            <Formik
              enableReinitialize={true}
              initialValues={{
                format: '',
                type: 'simple',
                contentMaxMarkings: [],
                fileMarkings: [],
                columns: 'all',
              }}
              validationSchema={exportValidation(t_i18n)}
              onSubmit={onSubmit.bind(null, selectedIds)}
              onReset={handleClose}
            >
              {({ submitForm, handleReset, isSubmitting, resetForm, values }) => (
                <Form>
                  <Dialog
                    open={open}
                    onClose={() => {
                      resetForm();
                      handleClose();
                    }}
                    data-testid="StixCyberObservablesExportCreationDialog"
                    title={(
                      <Stack direction="row" alignItems="center" gap={1}>
                        {t_i18n('Generate an export')}
                        <Tooltip title={t_i18n('Your max shareable markings will be applied to the content max markings')}>
                          <InfoOutlined fontSize="small" color="primary" />
                        </Tooltip>
                      </Stack>
                    )}
                  >
                    <QueryRenderer
                      query={markingDefinitionsLinesSearchQuery}
                      variables={{ first: 200 }}
                      render={({ props }) => {
                        if (props && props.markingDefinitions) {
                          return (
                            <>
                              <Field
                                component={SelectField}
                                variant="standard"
                                name="format"
                                label={t_i18n('Export format')}
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
                              <Field
                                component={SelectField}
                                variant="standard"
                                name="type"
                                label={t_i18n('Export type')}
                                fullWidth={true}
                                containerstyle={fieldSpacingContainerStyle}
                              >
                                <MenuItem value="simple">
                                  {t_i18n('Simple export (just the entity)')}
                                </MenuItem>
                                <MenuItem value="full">
                                  {t_i18n(
                                    'Full export (entity and first neighbours)',
                                  )}
                                </MenuItem>
                              </Field>
                              <ObjectMarkingField
                                name="contentMaxMarkings"
                                label={t_i18n(CONTENT_MAX_MARKINGS_TITLE)}
                                onChange={(_, values) => handleSelectedContentMaxMarkingsChange(values)}
                                style={fieldSpacingContainerStyle}
                                limitToMaxSharing
                                helpertext={t_i18n(CONTENT_MAX_MARKINGS_HELPERTEXT)}
                              />
                              <ObjectMarkingField
                                name="fileMarkings"
                                label={t_i18n('File marking definition levels')}
                                filterTargetIds={selectedContentMaxMarkingsIds}
                                style={fieldSpacingContainerStyle}
                              />
                              {visibleColumnExportEnabledFormats.includes(values.format)
                                ? (
                                    <Field
                                      component={SelectField}
                                      variant="standard"
                                      name="columns"
                                      label={t_i18n('Choose column to export')}
                                      fullWidth={true}
                                      containerstyle={fieldSpacingContainerStyle}
                                    >
                                      <MenuItem value="all">
                                        {t_i18n('All attributes')}
                                      </MenuItem>
                                      <MenuItem value="view">
                                        {t_i18n('Current view')}
                                      </MenuItem>
                                    </Field>
                                  ) : undefined}
                            </>
                          );
                        }
                        return <Loader variant="inElement" />;
                      }}
                    />
                    <DialogActions>
                      <Button variant="secondary" onClick={handleReset} disabled={isSubmitting}>
                        {t_i18n('Cancel')}
                      </Button>
                      <Button
                        onClick={submitForm}
                        disabled={isSubmitting}
                      >
                        {t_i18n('Create')}
                      </Button>
                    </DialogActions>
                  </Dialog>
                </Form>
              )}
            </Formik>
          </>
        );
      }}
    </ExportContext.Consumer>
  );
};

const StixCyberObservablesExportCreations = createFragmentContainer(
  StixCyberObservablesExportCreationComponent,
  {
    data: graphql`
      fragment StixCyberObservablesExportCreation_data on Query {
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

StixCyberObservablesExportCreations.propTypes = {
  classes: PropTypes.object.isRequired,
  data: PropTypes.object,
  paginationOptions: PropTypes.object,
  exportContext: PropTypes.object,
  onExportAsk: PropTypes.func,
};

export default withStyles(styles)(StixCyberObservablesExportCreations);
