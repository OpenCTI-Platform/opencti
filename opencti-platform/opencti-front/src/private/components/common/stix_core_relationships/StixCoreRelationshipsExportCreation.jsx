import Button from '@common/button/Button';
import Dialog from '@common/dialog/Dialog';
import { InfoOutlined } from '@mui/icons-material';
import DialogActions from '@mui/material/DialogActions';
import MenuItem from '@mui/material/MenuItem';
import Slide from '@mui/material/Slide';
import Tooltip from '@mui/material/Tooltip';
import withStyles from '@mui/styles/withStyles';
import { Field, Form, Formik } from 'formik';
import * as PropTypes from 'prop-types';
import * as R from 'ramda';
import React, { useState } from 'react';
import { createFragmentContainer, graphql } from 'react-relay';
import * as Yup from 'yup';
import SelectField from '../../../../components/fields/SelectField';
import { useFormatter } from '../../../../components/i18n';
import Loader from '../../../../components/Loader';
import { commitMutation, MESSAGING$, QueryRenderer } from '../../../../relay/environment';
import { ExportContext } from '../../../../utils/ExportContextProvider';
import { fieldSpacingContainerStyle } from '../../../../utils/field';
import { emptyFilterGroup, removeIdAndIncorrectKeysFromFilterGroupObject } from '../../../../utils/filters/filtersUtils';
import { UserContext } from '../../../../utils/hooks/useAuth';
import { markingDefinitionsLinesSearchQuery } from '../../settings/MarkingDefinitionsQuery';
import { CONTENT_MAX_MARKINGS_HELPERTEXT, CONTENT_MAX_MARKINGS_TITLE } from '../files/FileManager';
import ObjectMarkingField from '../form/ObjectMarkingField';

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

const StixCoreRelationshipsExportCreationComponent = (props) => {
  const { t_i18n } = useFormatter();
  const [selectedContentMaxMarkingsIds, setSelectedContentMaxMarkingsIds] = useState([]);
  const handleSelectedContentMaxMarkingsChange = (values) => {
    setSelectedContentMaxMarkingsIds(values.map(({ value }) => value));
  };

  const onSubmit = (selectedIds, availableFilterKeys, values, { setSubmitting, resetForm }) => {
    const { paginationOptions, exportContext } = props;
    const { orderBy, orderMode, filters, search } = paginationOptions;
    const contentMaxMarkings = values.contentMaxMarkings.map(({ value }) => value);
    const fileMarkings = values.fileMarkings.map(({ value }) => value);
    const finalFilters = filters ?? emptyFilterGroup;

    const updatedExportContext = { ...exportContext };
    // Only forward visible_columns for a "Current view" CSV export. The column
    // selector is hidden for other formats, so clear it otherwise (including
    // after the format is switched away from CSV) to avoid sending a stale
    // hidden-field value to the export connector.
    if (values.columns !== 'view' || values.format !== 'text/csv') {
      updatedExportContext.visible_columns = undefined;
    }

    commitMutation({
      mutation: StixCoreRelationshipsExportCreationMutation,
      variables: {
        input: {
          format: values.format,
          exportType: 'full',
          contentMaxMarkings,
          fileMarkings,
          exportContext: updatedExportContext,
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
        if (props.onExportAsk) props.onExportAsk();
        props.onClose();
        MESSAGING$.notifySuccess('Export successfully started');
      },
    });
  };

  const { data, open, onClose } = props;
  const connectorsExport = data?.connectorsForExport ?? [];
  const exportScopes = R.uniq(
    R.flatten(R.map((c) => c.connector_scope, connectorsExport)),
  );
  const exportConnsPerFormat = scopesConn(connectorsExport);

  const isExportActive = (format) => exportConnsPerFormat[format].filter((x) => x.data.active).length > 0;
  const visibleColumnExportEnabledFormats = ['text/csv'];

  return (
    <UserContext.Consumer>
      {({ schema }) => {
        const availableFilterKeys = Array.from(schema.filterKeysSchema.get('stix-core-relationship')?.keys() ?? []).concat(['entity_type']);
        return (
          <ExportContext.Consumer>
            {({ selectedIds }) => {
              return (
                <div>
                  <Formik
                    enableReinitialize={true}
                    initialValues={{
                      format: '',
                      contentMaxMarkings: [],
                      fileMarkings: [],
                      columns: 'all',
                    }}
                    validationSchema={exportValidation(t_i18n)}
                    onSubmit={onSubmit.bind(null, selectedIds, availableFilterKeys)}
                    onReset={onClose}
                  >
                    {({ submitForm, handleReset, isSubmitting, resetForm, setFieldValue, values }) => (
                      <Form>
                        <Dialog
                          data-testid="StixCoreRelationshipsExportCreationDialog"
                          open={open}
                          onClose={() => {
                            resetForm();
                            onClose();
                          }}
                          title={(
                            <>
                              {t_i18n('Generate an export')}
                              <Tooltip title={t_i18n('Your max shareable markings will be applied to the content max markings')}>
                                <InfoOutlined sx={{ paddingLeft: 1 }} fontSize="small" />
                              </Tooltip>
                            </>
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
                                    <ObjectMarkingField
                                      name="contentMaxMarkings"
                                      label={t_i18n(CONTENT_MAX_MARKINGS_TITLE)}
                                      onChange={(_, values) => handleSelectedContentMaxMarkingsChange(values)}
                                      style={fieldSpacingContainerStyle}
                                      setFieldValue={setFieldValue}
                                      limitToMaxSharing
                                      helpertext={t_i18n(CONTENT_MAX_MARKINGS_HELPERTEXT)}
                                    />
                                    <ObjectMarkingField
                                      name="fileMarkings"
                                      label={t_i18n('File marking definition levels')}
                                      filterTargetIds={selectedContentMaxMarkingsIds}
                                      style={fieldSpacingContainerStyle}
                                      setFieldValue={setFieldValue}
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
                                        )
                                      : undefined}
                                  </>
                                );
                              }
                              return <Loader variant="inElement" />;
                            }}
                          />
                          <DialogActions>
                            <Button
                              variant="secondary"
                              onClick={() => {
                                handleReset();
                                onClose();
                              }}
                              disabled={isSubmitting}
                            >
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
                </div>
              );
            }}
          </ExportContext.Consumer>
        );
      }}
    </UserContext.Consumer>
  );
};

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
  data: PropTypes.object,
  exportContext: PropTypes.object,
  paginationOptions: PropTypes.object,
  onExportAsk: PropTypes.func,
  open: PropTypes.boolean,
  onClose: PropTypes.func,
};

export default withStyles(styles)(StixCoreRelationshipsExportCreations);
