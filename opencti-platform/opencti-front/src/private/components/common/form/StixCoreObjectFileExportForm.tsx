import Button from '@common/button/Button';
import Dialog from '@common/dialog/Dialog';
import EETooltip from '@components/common/entreprise_edition/EETooltip';
import { CONTENT_MAX_MARKINGS_HELPERTEXT, CONTENT_MAX_MARKINGS_TITLE } from '@components/common/files/FileManager';
import FiligranIcon from '@components/common/FiligranIcon';
import ObjectMarkingField from '@components/common/form/ObjectMarkingField';
import { BUILT_IN_FROM_TEMPLATE, BUILT_IN_HTML_TO_PDF } from '@components/common/stix_core_objects/StixCoreObjectFileExport';
import { AbcOutlined, DataObjectOutlined, HtmlOutlined, NumbersOutlined } from '@mui/icons-material';
import { Stack } from '@mui/material';
import CardContent from '@mui/material/CardContent';
import DialogActions from '@mui/material/DialogActions';
import Grid from '@mui/material/Grid2';
import Step from '@mui/material/Step';
import StepButton from '@mui/material/StepButton';
import StepLabel from '@mui/material/StepLabel';
import Stepper from '@mui/material/Stepper';
import Tooltip from '@mui/material/Tooltip';
import Typography from '@mui/material/Typography';
import { LogoXtmOneIcon } from 'filigran-icon';
import { Field, Form, Formik } from 'formik';
import { FormikConfig } from 'formik/dist/types';
import { FileExportOutline, FilePdfBox, InformationOutline, LanguageMarkdownOutline } from 'mdi-material-ui';
import React, { useEffect, useRef, useState } from 'react';
import * as Yup from 'yup';
import ComboboxField from '../../../../components/ComboboxField';
import Alert from '../../../../components/Alert';
import Card from '../../../../components/common/card/Card';
import SelectFieldFds, { SelectItem } from '../../../../components/fields/SelectFieldFds';
import SwitchField from '../../../../components/fields/SwitchField';
import { useFormatter } from '../../../../components/i18n';
import TextField from '../../../../components/TextField';
import { FieldOption, fieldSpacingContainerStyle } from '../../../../utils/field';
import useAI from '../../../../utils/hooks/useAI';
import useEnterpriseEdition from '../../../../utils/hooks/useEnterpriseEdition';
import { nowUTC } from '../../../../utils/Time';
import { buildExportFileName, normalizeExportSourceEntityName } from './StixCoreObjectFileExportForm.utils';
import FintelDesignField, { FintelDesignFieldOption } from './FintelDesignField';

export type FileOption = Pick<FieldOption, 'label' | 'value'> & {
  fileName?: string;
  fileMarkings: {
    id: string;
    name: string;
  }[];
  fintelTemplateId?: string | null;
};

export type ConnectorOption = FieldOption & {
  connectorScope: readonly string[];
};

export type TemplateOption = FieldOption & {
  isDefault?: boolean;
  include_cover_page_by_default?: boolean;
  include_back_page_by_default?: boolean;
};

export interface StixCoreObjectFileExportFormInputs {
  connector: ConnectorOption | null;
  format: string;
  type: string | null;
  fileToExport: FileOption | null;
  template: TemplateOption | null;
  exportFileName: string | null;
  contentMaxMarkings: FieldOption[];
  fileMarkings: FieldOption[];
  fintelDesign: FintelDesignFieldOption | null;
  includeCoverPage: boolean;
  includeBackPage: boolean;
}

export interface StixCoreObjectFileExportFormProps {
  isOpen: boolean;
  onClose: () => void;
  onSubmit: FormikConfig<StixCoreObjectFileExportFormInputs>['onSubmit'];
  connectors: ConnectorOption[];
  templates?: TemplateOption[];
  fileOptions?: FileOption[];
  defaultFileMarkings?: FieldOption[];
  defaultTemplate?: TemplateOption;
  defaultValues?: {
    connector: string;
    format: string;
    fileToExport?: string;
  };
  scoName?: string;
  handleOpenAskAi: () => void;
  instanceType?: string | null | undefined;
}

export const renderIcon = (key: string) => {
  switch (key) {
    case 'ai':
      return <FiligranIcon icon={LogoXtmOneIcon} size="large" />;
    case 'application/pdf':
      return <FilePdfBox fontSize="large" color="primary" />;
    case 'application/json':
    case 'application/vnd.mitre.navigator+json':
    case 'application/vnd.oasis.stix+json':
      return <DataObjectOutlined fontSize="large" color="primary" />;
    case 'text/html':
      return <HtmlOutlined fontSize="large" color="primary" />;
    case 'text/markdown':
      return <LanguageMarkdownOutline fontSize="large" color="primary" />;
    case 'text/plain':
      return <AbcOutlined fontSize="large" color="primary" />;
    case 'text/csv':
      return <NumbersOutlined fontSize="large" color="primary" />;

    default:
      return <FileExportOutline fontSize="large" color="primary" />;
  }
};

const StixCoreObjectFileExportForm = ({
  isOpen,
  onClose,
  onSubmit,
  connectors,
  templates,
  fileOptions,
  defaultFileMarkings,
  defaultValues,
  defaultTemplate,
  scoName,
  handleOpenAskAi,
  instanceType,
}: StixCoreObjectFileExportFormProps) => {
  const { t_i18n } = useFormatter();
  const isEnterpriseEdition = useEnterpriseEdition();
  const { enabled, configured } = useAI();
  const lastAppliedPageDefaultsSource = useRef<string | null>(null);
  const [stepIndex, setStepIndex] = useState(defaultValues?.format ? 1 : 0);
  const [selectedContentMaxMarkingsIds, setSelectedContentMaxMarkingsIds] = useState<string[]>([]);
  const isBuiltInConnector = (connector?: string) => [BUILT_IN_FROM_TEMPLATE.value, BUILT_IN_HTML_TO_PDF.value].includes(connector ?? '');

  useEffect(() => {
    if (!isOpen) {
      lastAppliedPageDefaultsSource.current = null;
    }
  }, [isOpen]);

  const handleSelectedContentMaxMarkingsChange = (
    values: FieldOption[] | undefined,
    setFieldValue: (field: string, value: unknown) => void,
    fallbackFileMarkings: FieldOption[],
  ) => {
    const nextValues = values ?? [];
    setSelectedContentMaxMarkingsIds(nextValues.map(({ value }) => value));
    setFieldValue('fileMarkings', nextValues.length > 0 ? nextValues : fallbackFileMarkings);
  };

  const validation = () => Yup.object().shape({
    connector: Yup.object().required(t_i18n('This field is required')),
    format: Yup.string().trim().required(t_i18n('This field is required')),
    type: Yup.string().nullable().when('connector', {
      is: (val: ConnectorOption | null) => !isBuiltInConnector(val?.value),
      then: (schema) => schema.required(t_i18n('This field is required')),
    }),
    template: Yup.object().nullable().when('connector', {
      is: (val: ConnectorOption | null) => val?.value === BUILT_IN_FROM_TEMPLATE.value,
      then: (schema) => schema.required(t_i18n('This field is required')),
    }),
    fintelDesigns: Yup.object().nullable(),
    fileToExport: Yup.object().nullable().when('connector', {
      is: (val: ConnectorOption | null) => val?.value === BUILT_IN_HTML_TO_PDF.value,
      then: (schema) => schema.required(t_i18n('This field is required')),
    }),
    exportFileName: Yup.string().nullable().when('connector', {
      is: (val: ConnectorOption | null) => isBuiltInConnector(val?.value),
      then: (schema) => schema.required(t_i18n('This field is required')),
    }),
  });
  const connectorScopes = Array.from(new Set(connectors.flatMap((c) => c.connectorScope ?? [])));

  let selectedDefaultTemplate = defaultTemplate;
  if (defaultValues?.connector === BUILT_IN_FROM_TEMPLATE.value && !defaultTemplate) {
    [selectedDefaultTemplate] = templates ?? [];
  }
  const defaultFileToExport = fileOptions?.find((f) => f.value === defaultValues?.fileToExport);
  let defaultFormat = '';
  if (defaultValues?.format) {
    defaultFormat = defaultValues.format;
  } else if (connectorScopes.length > 0) {
    defaultFormat = connectorScopes.includes('application/pdf') ? 'application/pdf' : connectorScopes[0];
  }
  const initialValues: StixCoreObjectFileExportFormInputs = {
    connector: connectors.find((c) => c.value === defaultValues?.connector) ?? null,
    format: defaultFormat,
    type: null,
    template: selectedDefaultTemplate ?? null,
    fileToExport: defaultFileToExport ?? null,
    exportFileName: null,
    contentMaxMarkings: [],
    fintelDesign: null,
    includeCoverPage: true,
    includeBackPage: true,
    fileMarkings: defaultFileToExport?.fileMarkings.map(({ id, name }) => ({ label: name, value: id }))
      ?? defaultFileMarkings
      ?? [],
  };
  const isConnectorValid = (option: ConnectorOption, selectedFormat: string) => {
    if (!selectedFormat) return true;
    const connector = connectors.find((c) => c.value === option.value);
    return !!connector?.connectorScope?.includes(selectedFormat);
  };
  const selectFormat = (setFieldValue: (field: string, value: string) => void, scope: string) => {
    setFieldValue('format', scope);
    if (scope === 'ai') {
      handleOpenAskAi();
    } else {
      setStepIndex(1);
    }
  };
  const isContainer = ['Report', 'Case-Incident', 'Case-RFI'].includes(instanceType ?? 'Unknown');
  return (
    <Formik<StixCoreObjectFileExportFormInputs>
      enableReinitialize={true}
      initialValues={initialValues}
      validationSchema={validation}
      onSubmit={onSubmit}
    >
      {({ submitForm, handleReset, isSubmitting, setFieldValue, values }) => {
        useEffect(() => {
          if (values.connector !== null) {
            const connector = connectors.find((c) => c.value === values.connector?.value);
            const isCompatible = !!connector?.connectorScope?.includes(values.format);
            if (!isCompatible) setFieldValue('connector', null);
          }
        }, [values.format]);

        useEffect(() => {
          if (values.format) {
            const validConnectors = connectors.filter((c) => c.connectorScope?.includes(values.format));
            if (validConnectors.length === 1 && !values.connector) {
              setFieldValue('connector', validConnectors[0]);
            }
          }
        }, [values.format, connectors, values.connector, setFieldValue]);

        useEffect(() => {
          const connector = values.connector?.value;
          if (connector !== BUILT_IN_HTML_TO_PDF.value) setFieldValue('fileToExport', null);
          if (connector !== BUILT_IN_FROM_TEMPLATE.value) setFieldValue('template', null);
          if (!isBuiltInConnector(connector)) {
            setFieldValue('exportFileName', null);
          }
          if (connector === BUILT_IN_HTML_TO_PDF.value && values.fileToExport === null) {
            setFieldValue('fileToExport', (fileOptions ?? [])[0] ?? null);
          }
          if (connector === BUILT_IN_FROM_TEMPLATE.value && values.template === null) {
            setFieldValue('template', (templates ?? [])[0] ?? null);
          }
        }, [values.connector]);

        useEffect(() => {
          if (values.template || values.fileToExport) {
            const selectedEntityName = values.connector?.value === BUILT_IN_HTML_TO_PDF.value
              ? (values.fileToExport?.value === 'mappableContent'
                  ? scoName
                  : normalizeExportSourceEntityName(values.fileToExport?.fileName))
              : scoName;
            setFieldValue('exportFileName', buildExportFileName({
              entityName: selectedEntityName,
              markings: values.fileMarkings,
              utcIsoDate: nowUTC(),
            }));
          }
        }, [values.template, values.fileToExport, values.fileMarkings, scoName, setFieldValue]);

        useEffect(() => {
          setSelectedContentMaxMarkingsIds((values.contentMaxMarkings ?? []).map(({ value }) => value));
        }, [values.contentMaxMarkings]);

        useEffect(() => {
          const defaults = values.template;
          if (!defaults) return;
          const sourceKey = `template:${defaults.value}`;
          if (lastAppliedPageDefaultsSource.current === sourceKey) return;
          lastAppliedPageDefaultsSource.current = sourceKey;
          setFieldValue('includeCoverPage', defaults.include_cover_page_by_default ?? true);
          setFieldValue('includeBackPage', defaults.include_back_page_by_default ?? true);
        }, [setFieldValue, values.template?.value]);

        useEffect(() => {
          if (values.connector?.value !== BUILT_IN_HTML_TO_PDF.value) return;
          if (!values.fileToExport?.value.startsWith('fromTemplate/')) return;
          const originTemplateId = values.fileToExport.fintelTemplateId;
          if (!originTemplateId) return;
          const sourceKey = `file:${values.fileToExport.value}:${originTemplateId}`;
          if (lastAppliedPageDefaultsSource.current === sourceKey) return;
          const originTemplate = (templates ?? []).find((template) => template.value === originTemplateId);
          if (!originTemplate) return;
          lastAppliedPageDefaultsSource.current = sourceKey;
          setFieldValue('includeCoverPage', originTemplate.include_cover_page_by_default ?? true);
          setFieldValue('includeBackPage', originTemplate.include_back_page_by_default ?? true);
        }, [setFieldValue, templates, values.connector?.value, values.fileToExport?.value, values.fileToExport?.fintelTemplateId]);

        const shouldDisplayFintelDesign = (
          (values.connector?.value === BUILT_IN_FROM_TEMPLATE.value && values.format === 'application/pdf')
          || (values.connector?.value === BUILT_IN_HTML_TO_PDF.value && values.fileToExport?.value.startsWith('fromTemplate/'))
        );
        const shouldDisplayPageOptions = (
          values.connector?.value === BUILT_IN_HTML_TO_PDF.value
          || (values.connector?.value === BUILT_IN_FROM_TEMPLATE.value && values.format === 'application/pdf')
        );

        return (

          <Dialog
            open={isOpen}
            onClose={() => {
              handleReset();
              onClose();
            }}
            data-testid="StixCoreObjectFileExportDialog"
            title={(
              <Stack direction="row" alignItems="center" gap={1}>
                <Typography variant="h2" sx={{ margin: '0px!important' }}>
                  {t_i18n('Generate an export')}
                </Typography>
                <Tooltip title={t_i18n('Your max shareable markings will be applied to the content max markings')}>
                  <InformationOutline fontSize="small" color="primary" />
                </Tooltip>
              </Stack>
            )}
            size="large"
          >
            <Form>
              <Stepper nonLinear activeStep={stepIndex} sx={{ marginY: 3 }}>
                <Step>
                  <StepButton
                    onClick={() => setStepIndex(0)}
                    disabled={stepIndex === 0}
                  >
                    <StepLabel>{t_i18n('Format')}</StepLabel>
                  </StepButton>
                </Step>
                <Step>
                  <StepButton
                    onClick={() => setStepIndex(1)}
                    disabled={stepIndex <= 1}
                  >
                    <StepLabel>{t_i18n('Form')}</StepLabel>
                  </StepButton>
                </Step>
              </Stepper>

              {stepIndex === 0 && (
                <Grid
                  container={true}
                  spacing={3}
                  style={{ marginTop: 0, marginBottom: 0 }}
                >
                  {connectorScopes.map((scope) => (
                    <Grid key={scope} size={{ xs: 4 }}>
                      <Card
                        aria-label={t_i18n(scope)}
                        onClick={() => selectFormat(setFieldValue, scope)}
                        variant="outlined"
                        sx={{
                          textAlign: 'center',
                          height: 150,
                          display: 'flex',
                          flexDirection: 'column',
                          p: 1,
                        }}
                      >
                        <CardContent>
                          {renderIcon(scope)}
                          <Typography
                            variant="body1"
                            sx={{
                              wordWrap: 'break-word',
                              overflowWrap: 'break-word',
                              wordBreak: 'break-word',
                              mt: 1,
                            }}
                          >
                            {t_i18n(scope)}
                          </Typography>
                        </CardContent>
                      </Card>
                    </Grid>
                  ))}
                  {isContainer && (enabled && configured) && (
                    <Grid size={{ xs: 4 }}>
                      <Card
                        aria-label={t_i18n('Ask AI')}
                        variant="outlined"
                        onClick={() => (isEnterpriseEdition && (enabled && configured) ? selectFormat(setFieldValue, 'ai') : null)}
                        sx={{
                          textAlign: 'center',
                          height: 150,
                          display: 'flex',
                          flexDirection: 'column',
                          p: 1,
                        }}
                      >
                        <EETooltip forAi={true} title={t_i18n('Ask AI (multiple formats supported)')}>
                          <CardContent sx={{
                            display: 'flex',
                            flexDirection: 'column',
                            justifyContent: 'center',
                            alignItems: 'center',
                          }}
                          >
                            {renderIcon('ai')}
                            <Typography
                              variant="body1"
                              sx={{
                                wordWrap: 'break-word',
                                overflowWrap: 'break-word',
                                wordBreak: 'break-word',
                                mt: 1,
                              }}
                            >
                              {t_i18n('Ask AI (multiple formats supported)')}
                            </Typography>
                          </CardContent>
                        </EETooltip>
                      </Card>
                    </Grid>
                  )}
                </Grid>
              )}
              {stepIndex === 1 && (
                <>
                  <Field
                    component={ComboboxField}
                    name="connector"
                    disabled={!values.format}
                    style={fieldSpacingContainerStyle}
                    options={connectors}
                    isOptionDisabled={(option: ConnectorOption) => !isConnectorValid(option, values.format)}
                    renderOption={(option: FieldOption) => option.label}
                    label={t_i18n('Connector')}
                    autoFocus
                  />
                  {values.connector && (
                    <>
                      {values.connector.value === BUILT_IN_FROM_TEMPLATE.value && (
                        <Field
                          component={ComboboxField}
                          name="template"
                          style={fieldSpacingContainerStyle}
                          options={templates}
                          renderOption={(option: FieldOption) => option.label}
                          label={t_i18n('Template')}
                        />
                      )}
                      {values.connector.value === BUILT_IN_HTML_TO_PDF.value && (
                        <Field
                          component={ComboboxField}
                          name="fileToExport"
                          style={fieldSpacingContainerStyle}
                          options={fileOptions}
                          renderOption={(option: FieldOption) => option.label}
                          label={t_i18n('File to export')}
                          helperText={t_i18n('A FINTEL export will contain extra information like markings and creation date')}
                        />
                      )}
                      {shouldDisplayFintelDesign && (
                        <FintelDesignField
                          name="fintelDesign"
                          label={t_i18n('Fintel design')}
                          style={fieldSpacingContainerStyle}
                        />
                      )}
                      {!isBuiltInConnector(values.connector.value) && (
                        <Field
                          component={SelectFieldFds}
                          variant="standard"
                          name="type"
                          aria-label="TYPE"
                          label={t_i18n('Export type')}
                          fullWidth={true}
                          containerstyle={fieldSpacingContainerStyle}
                        >
                          <SelectItem value="simple">
                            {t_i18n('Simple export (just the entity)')}
                          </SelectItem>
                          <SelectItem value="full">
                            {t_i18n('Full export (entity and first neighbours)')}
                          </SelectItem>
                        </Field>
                      )}
                      {isBuiltInConnector(values.connector.value) && (
                        <Field
                          component={TextField}
                          variant="standard"
                          name="exportFileName"
                          label={t_i18n('Export file name')}
                          className="mt-5"
                        />
                      )}
                      {values.connector.value !== BUILT_IN_HTML_TO_PDF.value && (
                        <ObjectMarkingField
                          name="contentMaxMarkings"
                          label={t_i18n(CONTENT_MAX_MARKINGS_TITLE)}
                          onChange={(_, updatedValues) => handleSelectedContentMaxMarkingsChange(
                            updatedValues,
                            setFieldValue,
                            defaultFileMarkings ?? [],
                          )}
                          style={fieldSpacingContainerStyle}
                          setFieldValue={setFieldValue}
                          limitToMaxSharing
                          helpertext={t_i18n(CONTENT_MAX_MARKINGS_HELPERTEXT)}
                        />
                      )}
                      <ObjectMarkingField
                        name="fileMarkings"
                        label={t_i18n('File marking definition levels')}
                        filterTargetIds={selectedContentMaxMarkingsIds}
                        style={fieldSpacingContainerStyle}
                        setFieldValue={setFieldValue}
                      />
                      {shouldDisplayPageOptions && (
                        <>
                          <Typography variant="h3" sx={{ marginTop: 3 }}>
                            {t_i18n('Page options')}
                          </Typography>
                          <Field
                            component={SwitchField}
                            type="checkbox"
                            name="includeCoverPage"
                            label={t_i18n('Include cover page')}
                            containerstyle={{ marginTop: 10 }}
                          />
                          <Field
                            component={SwitchField}
                            type="checkbox"
                            name="includeBackPage"
                            label={t_i18n('Include back page')}
                            containerstyle={{ marginTop: 10 }}
                          />
                          {(!values.includeCoverPage || !values.includeBackPage) && (
                            <Alert
                              style={{ marginTop: 10 }}
                              content={t_i18n(
                                !values.includeCoverPage && !values.includeBackPage
                                  ? 'The PDF will start and end on content pages only.'
                                  : !values.includeCoverPage
                                      ? 'The PDF will start on the first content page.'
                                      : 'The PDF will end on the last content page.',
                              )}
                            />
                          )}
                        </>
                      )}
                    </>
                  )}
                </>
              )}

              <DialogActions>
                <Button
                  variant="secondary"
                  disabled={isSubmitting}
                  onClick={() => {
                    handleReset();
                    onClose();
                  }}
                >
                  {t_i18n('Cancel')}
                </Button>
                <Button
                  onClick={submitForm}
                  disabled={isSubmitting || stepIndex === 0}
                >
                  {t_i18n('Create')}
                </Button>
              </DialogActions>
            </Form>
          </Dialog>
        );
      }}
    </Formik>
  );
};

export default StixCoreObjectFileExportForm;
