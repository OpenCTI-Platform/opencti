import React, { useState } from 'react';
import * as R from 'ramda';
import { filter } from 'ramda';
import Tooltip from '@mui/material/Tooltip';
import { FileExportOutline } from 'mdi-material-ui';
import ToggleButton from '@mui/material/ToggleButton';
import DialogTitle from '@mui/material/DialogTitle';
import Dialog from '@mui/material/Dialog';
import { Field, Form, Formik } from 'formik';
import DialogActions from '@mui/material/DialogActions';
import DialogContent from '@mui/material/DialogContent';
import Button from '@mui/material/Button';
import * as Yup from 'yup';
import MenuItem from '@mui/material/MenuItem';
import { graphql, PreloadedQuery, usePreloadedQuery } from 'react-relay';
import { createSearchParams, useNavigate } from 'react-router-dom';
import { FormikHelpers } from 'formik/dist/types';
import { FileManagerExportMutation } from '@components/common/files/__generated__/FileManagerExportMutation.graphql';
import { StixCoreObjectFileExportQuery } from '@components/common/stix_core_objects/__generated__/StixCoreObjectFileExportQuery.graphql';
import { MarkingDefinitionsLinesSearchQuery$data } from '@components/settings/marking_definitions/__generated__/MarkingDefinitionsLinesSearchQuery.graphql';
import { scopesConn } from '@components/common/stix_core_objects/StixCoreObjectFilesAndHistory';
import ObjectMarkingField from '@components/common/form/ObjectMarkingField';
import { Option } from '@components/common/form/ReferenceField';
import { InfoOutlined } from '@mui/icons-material';
import { markingDefinitionsLinesSearchQuery } from '../../settings/marking_definitions/MarkingDefinitionsLines';
import { fileManagerExportMutation } from '../files/FileManager';
import useQueryLoading from '../../../../utils/hooks/useQueryLoading';
import Loader, { LoaderVariant } from '../../../../components/Loader';
import { fieldSpacingContainerStyle } from '../../../../utils/field';
import SelectField from '../../../../components/fields/SelectField';
import { useFormatter } from '../../../../components/i18n';
import { handleErrorInForm, MESSAGING$, QueryRenderer } from '../../../../relay/environment';
import { resolveLink } from '../../../../utils/Entity';
import useApiMutation from '../../../../utils/hooks/useApiMutation';

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
  format: Yup.string().trim().required(t('This field is required')),
  type: Yup.string().required(t('This field is required')),
});
interface StixCoreObjectFileExportComponentProps {
  queryRef: PreloadedQuery<StixCoreObjectFileExportQuery>;
  id: string;
  type: string;
  redirectToContent?: boolean;
}

interface FormValues {
  format: string;
  type: string;
  contentMaxMarkings: Option[];
  fileMarkings: Option[];
}

const StixCoreObjectFileExportComponent = ({
  queryRef,
  id,
  type,
  redirectToContent,
}: StixCoreObjectFileExportComponentProps) => {
  const navigate = useNavigate();
  const { t_i18n } = useFormatter();
  const data = usePreloadedQuery<StixCoreObjectFileExportQuery>(
    stixCoreObjectFileExportQuery,
    queryRef,
  );
  const [commitExport] = useApiMutation<FileManagerExportMutation>(
    fileManagerExportMutation,
  );
  const [open, setOpen] = useState(false);
  const [selectedContentMaxMarkingsIds, setSelectedContentMaxMarkingsIds] = useState(['']);
  const handleSelectedContentMaxMarkingsChange = (values: Option[]) => setSelectedContentMaxMarkingsIds(values.map(({ value }) => value));
  const onSubmitExport = (
    values: FormValues,
    { setSubmitting, setErrors, resetForm }: FormikHelpers<FormValues>,
  ) => {
    const contentMaxMarkings = values.contentMaxMarkings.map(({ value }) => value);
    const fileMarkings = values.fileMarkings.map(({ value }) => value);
    commitExport({
      variables: {
        id,
        input: {
          format: values.format,
          exportType: values.type,
          contentMaxMarkings,
          fileMarkings,
        },
      },
      onError: (error) => {
        handleErrorInForm(error, setErrors);
        setSubmitting(false);
      },
      onCompleted: (exportData) => {
        const fileId = exportData.stixCoreObjectEdit?.exportAsk?.[0].id;
        setSubmitting(false);
        resetForm();
        MESSAGING$.notifySuccess('Export successfully started');
        navigate({
          pathname:
            values.format === 'application/pdf' && redirectToContent
              ? `${resolveLink(type)}/${id}/content`
              : `${resolveLink(type)}/${id}/files`,
          search: fileId
            ? `?${createSearchParams({ currentFileId: fileId })}`
            : '',
        });
      },
    });
  };
  const handleClickOpen = () => {
    setOpen(true);
  };
  const connectorsExport = data.connectorsForExport ?? [];
  const exportScopes = R.uniq(
    connectorsExport.map((c) => c?.connector_scope).flat(),
  );
  // All formats are supported PDF is selected by default if available
  // Redirecting to content for PDF export, to file for everything else
  const exportConnsPerFormat = scopesConn(connectorsExport);
  const isExportActive = (format: string) => filter((x) => x.data.active, exportConnsPerFormat[format]).length > 0;
  const formatValue = exportScopes.filter((s) => s === 'application/pdf').length > 0
    && isExportActive('application/pdf')
    ? 'application/pdf'
    : '';
  const isExportPossible = filter((x) => isExportActive(x ?? ''), exportScopes).length > 0;
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
        <span>
          <ToggleButton
            onClick={() => handleClickOpen()}
            disabled={!isExportPossible}
            value="quick-export"
            aria-label="Quick export"
            aria-haspopup="true"
            color="primary"
            size="small"
            style={{ marginRight: 3 }}
            data-testid="StixCoreObjectFileExportQuickExportButton"
          >
            <FileExportOutline
              fontSize="small"
              color={isExportPossible ? 'primary' : 'disabled'}
            />
          </ToggleButton>
        </span>
      </Tooltip>
      <Formik<FormValues>
        enableReinitialize={true}
        initialValues={{
          format: formatValue,
          type: 'full',
          contentMaxMarkings: [],
          fileMarkings: [],
        }}
        validationSchema={exportValidation(t_i18n)}
        onSubmit={onSubmitExport}
        onReset={() => setOpen(false)}
      >
        {({ submitForm, handleReset, isSubmitting, resetForm, setFieldValue }) => (
          <Form>
            <Dialog
              PaperProps={{ elevation: 1 }}
              open={open}
              onClose={resetForm}
              fullWidth={true}
              data-testid="StixCoreObjectFileExportDialog"
            >
              <DialogTitle>
                {t_i18n('Generate an export')}
                <Tooltip title={t_i18n('Your max shareable markings will be applied to the content max markings')}>
                  <InfoOutlined sx={{ paddingLeft: 1 }} fontSize="small" />
                </Tooltip>
              </DialogTitle>
              {/* Duplicate code for displaying list of marking in select input. TODO a component */}
              <QueryRenderer
                query={markingDefinitionsLinesSearchQuery}
                variables={{ first: 200 }}
                render={({
                  props,
                }: {
                  props: MarkingDefinitionsLinesSearchQuery$data;
                }) => {
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
                              value={value ?? ''}
                              disabled={!isExportActive(value ?? '')}
                            >
                              {value}
                            </MenuItem>
                          ))}
                        </Field>
                        <Field
                          component={SelectField}
                          variant="standard"
                          name="type"
                          aria-label={'TYPE'}
                          label={t_i18n('Export type')}
                          fullWidth={true}
                          containerstyle={fieldSpacingContainerStyle}
                        >
                          <MenuItem value="simple">
                            {t_i18n('Simple export (just the entity)')}
                          </MenuItem>
                          <MenuItem value="full">
                            {t_i18n('Full export (entity and first neighbours)')}
                          </MenuItem>
                        </Field>
                        <ObjectMarkingField
                          name="contentMaxMarkings"
                          label={t_i18n('Content max marking definition levels')}
                          onChange={(_, values) => handleSelectedContentMaxMarkingsChange(values)}
                          style={fieldSpacingContainerStyle}
                          setFieldValue={setFieldValue}
                          limitToMaxSharing
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
                  return <Loader variant={LoaderVariant.inElement} />;
                }}
              />
              <DialogActions>
                <Button onClick={handleReset} disabled={isSubmitting}>
                  Cancel
                </Button>
                <Button
                  color="secondary"
                  onClick={(e) => {
                    e.preventDefault();
                    submitForm();
                  }}
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
};

const StixCoreObjectFileExport = ({
  id,
  type,
  redirectToContent,
}: {
  id: string;
  type: string;
  redirectToContent?: boolean;
}) => {
  const queryRef = useQueryLoading<StixCoreObjectFileExportQuery>(
    stixCoreObjectFileExportQuery,
  );
  return (
    <>
      {queryRef && (
        <React.Suspense
          fallback={
            <ToggleButton
              value="quick-export"
              size="small"
              style={{ marginRight: 3 }}
              disabled={true}
            >
              <FileExportOutline fontSize="small" />
            </ToggleButton>
          }
        >
          <StixCoreObjectFileExportComponent
            id={id}
            type={type}
            queryRef={queryRef}
            redirectToContent={redirectToContent}
          />
        </React.Suspense>
      )}
    </>
  );
};

export default StixCoreObjectFileExport;
