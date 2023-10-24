import React, { useState } from 'react';
import { map } from 'ramda';
import Tooltip from '@mui/material/Tooltip';
import { FileExportOutline } from 'mdi-material-ui';
import ToggleButton from '@mui/material/ToggleButton';
import { DialogTitle } from '@mui/material';
import Dialog from '@mui/material/Dialog';
import { Field, Form, Formik } from 'formik';
import DialogActions from '@mui/material/DialogActions';
import DialogContent from '@mui/material/DialogContent';
import Button from '@mui/material/Button';
import * as Yup from 'yup';
import MenuItem from '@mui/material/MenuItem';
import { graphql, usePreloadedQuery } from 'react-relay';
import * as R from 'ramda';
import { useNavigate } from 'react-router-dom-v5-compat';
import { markingDefinitionsLinesSearchQuery } from '../../settings/marking_definitions/MarkingDefinitionsLines';
import { fileManagerExportMutation } from '../files/FileManager';
import useQueryLoading from '../../../../utils/hooks/useQueryLoading';
import Loader, { LoaderVariant } from '../../../../components/Loader';
import { fieldSpacingContainerStyle } from '../../../../utils/field';
import SelectField from '../../../../components/SelectField';
import { useFormatter } from '../../../../components/i18n';
import { commitMutation, MESSAGING$, QueryRenderer } from '../../../../relay/environment';

const stixCoreObjectFileExportQuery = graphql`
    query StixCoreObjectFileExportQuery {
        connectorsForExport {
            id
            name
            active
            connector_scope
            updated_at
        }
    }
`;

const exportValidation = (t) => Yup.object().shape({
  format: Yup.string().required(t('This field is required')),
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

const StixCoreObjectFileExportComponent = ({
  queryRef,
  id,
}) => {
  const onSubmitExport = (values, { setSubmitting, resetForm }) => {
    const maxMarkingDefinition = values.maxMarkingDefinition === 'none'
      ? null
      : values.maxMarkingDefinition;
    commitMutation({
      mutation: fileManagerExportMutation,
      variables: {
        id,
        format: values.format,
        exportType: values.type,
        maxMarkingDefinition,
      },

      onCompleted: () => {
        setSubmitting(false);
        resetForm();
        MESSAGING$.notifySuccess('Export successfully started');
      },
    });
  };

  const { t } = useFormatter();

  const [open, setOpen] = useState(false);
  const handleClickOpen = () => {
    setOpen(true);
  };

  const navigate = useNavigate();

  const data = usePreloadedQuery(
    stixCoreObjectFileExportQuery,
    queryRef,
  );
  const connectorsExport = R.propOr([], 'connectorsForExport', data);
  const exportScopes = R.uniq(
    R.flatten(R.map((c) => c.connector_scope, connectorsExport)),
  );

  const formatValue = exportScopes[0];

  const exportConnsPerFormat = scopesConn(connectorsExport);
  const isExportActive = (format) => R.filter((x) => x.data.active, exportConnsPerFormat[format]).length > 0;
  const isExportPossible = R.filter((x) => isExportActive(x), exportScopes).length > 0;

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
        <ToggleButton
          onClick={handleClickOpen}
          disabled={!isExportPossible}
          value="quick-export"
          aria-haspopup="true"
          color="primary"
          size="small"
          style={{ marginRight: 3 }}
        >
          <FileExportOutline
            fontSize="small"
            color="primary"
          />
        </ToggleButton>
      </Tooltip>
      <Formik
        enableReinitialize={true}
        initialValues={{
          format: formatValue,
          type: 'full',
          maxMarkingDefinition: 'none',
        }}
        validationSchema={exportValidation(t)}
        onSubmit={onSubmitExport}
        onReset={() => setOpen(false)}
      >
        {({ submitForm, handleReset, isSubmitting }) => (
          <Form>
            <Dialog PaperProps={{ elevation: 1 }}
                    open={open}
                    onClose={() => setOpen(false)}
                    fullWidth={true}>
              <DialogTitle>{t('Generate an export')}</DialogTitle>
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
                          containerstyle={fieldSpacingContainerStyle}
                        >
                          {exportScopes.map((value, i) => (
                            <MenuItem
                              key={i}
                              value={value}
                            >
                              {value}
                            </MenuItem>
                          ))}
                        </Field>
                        <Field
                          component={SelectField}
                          variant="standard"
                          name="type"
                          label={t('Export type')}
                          fullWidth={true}
                          containerstyle={fieldSpacingContainerStyle}
                        >
                          <MenuItem value="simple">
                            {t('Simple export (just the entity)')}
                          </MenuItem>
                          <MenuItem value="full">
                            {t('Full export (entity and first neighbours)')}
                          </MenuItem>
                        </Field>
                        <Field
                          component={SelectField}
                          variant="standard"
                          name="maxMarkingDefinition"
                          label={t('Max marking definition level')}
                          fullWidth={true}
                          containerstyle={fieldSpacingContainerStyle}
                        >
                          <MenuItem value="none">{t('None')}</MenuItem>
                          {map(
                            (markingDefinition) => (
                              <MenuItem
                                key={markingDefinition.node.id}
                                value={markingDefinition.node.id}
                              >
                                {markingDefinition.node.definition}
                              </MenuItem>
                            ),
                            props.markingDefinitions.edges,
                          )}
                        </Field>
                      </DialogContent>
                    );
                  }
                  return <Loader variant="inElement"/>;
                }}
              />
              <DialogActions>
                <Button onClick={handleReset} disabled={isSubmitting}>Cancel</Button>
                <Button
                  color="secondary"
                  onClick={(e) => {
                    e.preventDefault();
                    submitForm();
                    navigate(`/dashboard/analyses/reports/${id}/content`);
                  }}
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
};

const StixCoreObjectFileExport = (
  { id },
) => {
  const queryRef = useQueryLoading(stixCoreObjectFileExportQuery, { id });

  return queryRef ? (
    <React.Suspense fallback={<Loader variant={LoaderVariant.inElement}/>}>
      <StixCoreObjectFileExportComponent id={id} queryRef={queryRef}/>
    </React.Suspense>
  ) : (
    <Loader variant={LoaderVariant.inElement}/>
  );
};

export default StixCoreObjectFileExport;
