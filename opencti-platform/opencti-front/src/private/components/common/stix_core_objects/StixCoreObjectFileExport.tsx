import React, { useState } from 'react';
import * as R from 'ramda';
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
import { graphql, PreloadedQuery, useMutation, usePreloadedQuery } from 'react-relay';
import { createSearchParams, useNavigate } from 'react-router-dom-v5-compat';
import { FormikHelpers } from 'formik/dist/types';
import { FileManagerExportMutation } from '@components/common/files/__generated__/FileManagerExportMutation.graphql';
import {
  StixCoreObjectFileExportQuery,
} from '@components/common/stix_core_objects/__generated__/StixCoreObjectFileExportQuery.graphql';
import {
  MarkingDefinitionsLinesSearchQuery$data,
} from '@components/settings/marking_definitions/__generated__/MarkingDefinitionsLinesSearchQuery.graphql';
import { markingDefinitionsLinesSearchQuery } from '../../settings/marking_definitions/MarkingDefinitionsLines';
import { fileManagerExportMutation } from '../files/FileManager';
import useQueryLoading from '../../../../utils/hooks/useQueryLoading';
import Loader, { LoaderVariant } from '../../../../components/Loader';
import { fieldSpacingContainerStyle } from '../../../../utils/field';
import SelectField from '../../../../components/SelectField';
import { useFormatter } from '../../../../components/i18n';
import { MESSAGING$, QueryRenderer } from '../../../../relay/environment';

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

const exportValidation = (t: (arg: string) => string) => Yup.object().shape({
  format: Yup.string().required(t('This field is required')),
});
interface StixCoreObjectFileExportComponentProps {
  queryRef: PreloadedQuery<StixCoreObjectFileExportQuery>
  id: string
}

interface FormValues {
  format: string;
  type: string;
  maxMarkingDefinition: string | null;
}

const StixCoreObjectFileExportComponent = ({
  queryRef,
  id,
}:StixCoreObjectFileExportComponentProps) => {
  const navigate = useNavigate();
  const { t } = useFormatter();

  const data = usePreloadedQuery<StixCoreObjectFileExportQuery>(
    stixCoreObjectFileExportQuery,
    queryRef,
  );
  const [commitExport] = useMutation<FileManagerExportMutation>(fileManagerExportMutation);
  const [open, setOpen] = useState(false);

  const onSubmitExport = (values: FormValues, { setSubmitting, resetForm }: FormikHelpers<FormValues>) => {
    const maxMarkingDefinition = values.maxMarkingDefinition === 'none'
      ? null
      : values.maxMarkingDefinition;
    commitExport({
      variables: {
        id,
        format: values.format,
        exportType: values.type,
        maxMarkingDefinition,
      },

      onCompleted: (exportData) => {
        const fileId = exportData.stixCoreObjectEdit?.exportAsk?.[0].id;
        setSubmitting(false);
        resetForm();
        MESSAGING$.notifySuccess('Export successfully started');
        navigate({
          pathname: `/dashboard/analyses/reports/${id}/content`,
          search: fileId ? `?${createSearchParams({ currentFileId: fileId })}` : '',
        });
      },
    });
  };

  const handleClickOpen = () => {
    setOpen(true);
  };

  const connectorsExport = data.connectorsForExport ?? [];

  const exportScopes = R.uniq(connectorsExport.map((c) => c?.connector_scope).flat());

  // Handling only pdf for now
  const formatValue = 'application/pdf';

  const isExportPossible = connectorsExport.some((connector) => {
    return connector?.connector_scope?.includes(formatValue) && connector?.active;
  });

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
          onClick={() => handleClickOpen()}
          disabled={!isExportPossible}
          value="quick-export"
          aria-haspopup="true"
          color="primary"
          size="small"
          style={{ marginRight: 3 }}
        >
          <FileExportOutline
            fontSize="small"
            color={isExportPossible ? 'primary' : 'disabled' }
          />
        </ToggleButton>
      </Tooltip>
      <Formik<FormValues>
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
            <Dialog
              PaperProps={{ elevation: 1 }}
              open={open}
              onClose={() => setOpen(false)}
              fullWidth={true}
            >
              <DialogTitle>{t('Generate an export')}</DialogTitle>
              {/* Duplicate code for displaying list of marking in select input. TODO a component */}
              <QueryRenderer
                query={markingDefinitionsLinesSearchQuery}
                variables={{ first: 200 }}
                render={({ props }: { props: MarkingDefinitionsLinesSearchQuery$data }) => {
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
                          disabled
                        >
                          {exportScopes.map((value, i) => (
                            <MenuItem
                              key={i}
                              value={value ?? ''}
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
                  return <Loader variant={LoaderVariant.inElement} />;
                }}
              />
              <DialogActions>
                <Button onClick={handleReset} disabled={isSubmitting}>Cancel</Button>
                <Button
                  color="secondary"
                  onClick={(e) => {
                    e.preventDefault();
                    submitForm();
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
  { id }: { id: string },
) => {
  const queryRef = useQueryLoading<StixCoreObjectFileExportQuery>(stixCoreObjectFileExportQuery, { id });

  return queryRef ? (
    <React.Suspense fallback={<Loader variant={LoaderVariant.inElement} />}>
      <StixCoreObjectFileExportComponent id={id} queryRef={queryRef} />
    </React.Suspense>
  ) : (
    <Loader variant={LoaderVariant.inElement} />
  );
};

export default StixCoreObjectFileExport;
