import React, { useState } from 'react';
import * as R from 'ramda';
import Dialog from '@mui/material/Dialog';
import DialogTitle from '@mui/material/DialogTitle';
import DialogContent from '@mui/material/DialogContent';
import DialogActions from '@mui/material/DialogActions';
import Button from '@common/button/Button';
import { InfoOutlined } from '@mui/icons-material';
import { graphql } from 'react-relay';
import { Field, Form, Formik } from 'formik';
import MenuItem from '@mui/material/MenuItem';
import * as Yup from 'yup';
import Tooltip from '@mui/material/Tooltip';
import { CONTENT_MAX_MARKINGS_HELPERTEXT, CONTENT_MAX_MARKINGS_TITLE } from '../files/FileManager';
import ObjectMarkingField from '../form/ObjectMarkingField';
import { useFormatter } from '../../../../components/i18n';
import { commitMutation, MESSAGING$, QueryRenderer } from '../../../../relay/environment';
import { markingDefinitionsLinesSearchQuery } from '../../settings/MarkingDefinitionsQuery';
import SelectField from '../../../../components/fields/SelectField';
import Loader from '../../../../components/Loader';
import { ExportContext } from '../../../../utils/ExportContextProvider';
import { fieldSpacingContainerStyle } from '../../../../utils/field';

export const StixCoreObjectsExportCreationMutation = graphql`
  mutation StixCoreObjectsExportCreationMutation(
    $input: StixCoreObjectsExportAskInput!
  ) {
    stixCoreObjectsExportAsk(input: $input) {
      id
    }
  }
`;

const exportValidation = (t_i18n) => Yup.object().shape({
  format: Yup.string().trim().required(t_i18n('This field is required')),
});

export const scopesConn = (exportConnectors) => {
  const scopes = R.uniq(
    R.flatten(R.map((c) => c.connector_scope, exportConnectors)),
  );
  const connectors = R.map((s) => {
    const filteredConnectors = R.filter(
      (e) => R.includes(s, e.connector_scope),
      exportConnectors,
    );
    return R.map(
      (x) => ({ data: { name: x.name, active: x.active } }),
      filteredConnectors,
    );
  }, scopes);
  const zipped = R.zip(scopes, connectors);
  return R.fromPairs(zipped);
};

const StixCoreObjectsExportCreation = ({
  paginationOptions,
  exportContext,
  onExportAsk,
  exportType,
  exportScopes,
  isExportActive,
  open,
  setOpen,
}) => {
  const { t_i18n } = useFormatter();

  const [selectedContentMaxMarkingsIds, setSelectedContentMaxMarkingsIds] = useState([]);
  const handleSelectedContentMaxMarkingsChange = (values) => setSelectedContentMaxMarkingsIds(values.map(({ value }) => value));
  const onSubmit = (selectedIds, values, { setSubmitting, resetForm }) => {
    const { orderBy, filters, orderMode, search } = paginationOptions;
    const contentMaxMarkings = values.contentMaxMarkings.map(({ value }) => value);
    const fileMarkings = values.fileMarkings.map(({ value }) => value);
    commitMutation({
      mutation: StixCoreObjectsExportCreationMutation,
      variables: {
        input: {
          exportContext,
          format: values.format,
          exportType: exportType ?? 'full',
          selectedIds,
          orderBy,
          filters,
          orderMode,
          contentMaxMarkings,
          fileMarkings,
          search,
        },
      },
      onCompleted: () => {
        setSubmitting(false);
        resetForm();
        if (onExportAsk) onExportAsk();
        setOpen(false);
        MESSAGING$.notifySuccess('Export successfully started');
      },
    });
  };

  return (
    <ExportContext.Consumer>
      {({ selectedIds }) => {
        return (
          <Formik
            enableReinitialize={true}
            initialValues={{
              format: '',
              contentMaxMarkings: [],
              fileMarkings: [],
            }}
            validationSchema={exportValidation(t_i18n)}
            onSubmit={(values, { setSubmitting, resetForm }) => onSubmit(selectedIds, values, { setSubmitting, resetForm })
            }
            onReset={() => setOpen(false)}
          >
            {({ submitForm, handleReset, isSubmitting, resetForm, setFieldValue }) => (
              <Form>
                <Dialog
                  slotProps={{ paper: { elevation: 1 } }}
                  open={open}
                  onClose={() => {
                    resetForm();
                    setOpen(false);
                  }}
                  fullWidth={true}
                  data-testid="StixCoreObjectsExportCreationDialog"
                >
                  <DialogTitle>
                    {t_i18n('Generate an export')}
                    <Tooltip title={t_i18n('Your max shareable markings will be applied to the content max markings')}>
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
                          </DialogContent>
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
                      // color="secondary"
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
        );
      }}
    </ExportContext.Consumer>
  );
};

export default StixCoreObjectsExportCreation;
