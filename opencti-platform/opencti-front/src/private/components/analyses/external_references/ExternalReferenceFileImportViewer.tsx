import Button from '@common/button/Button';
import Dialog from '@common/dialog/Dialog';
import { FileManagerAskJobImportMutation$variables } from '@components/common/files/__generated__/FileManagerAskJobImportMutation.graphql';
import { CsvMapperFieldOption } from '@components/common/form/CsvMapperField';
import ObjectMarkingField from '@components/common/form/ObjectMarkingField';
import ManageImportConnectorMessage from '@components/data/import/ManageImportConnectorMessage';
import DialogActions from '@mui/material/DialogActions';
import List from '@mui/material/List';
import MenuItem from '@mui/material/MenuItem';
import { Field, Form, Formik } from 'formik';
import { FormikConfig } from 'formik/dist/types';
import { compose, includes } from 'ramda';
import React, { FunctionComponent, useEffect, useState } from 'react';
import { createRefetchContainer, graphql, RelayRefetchProp } from 'react-relay';
import { FragmentRefs } from 'relay-runtime';
import { interval } from 'rxjs';
import * as Yup from 'yup';
import Card from '../../../../components/common/card/Card';
import SelectField from '../../../../components/fields/SelectField';
import inject18n, { useFormatter } from '../../../../components/i18n';
import UploadImport from '../../../../components/UploadImport';
import { commitMutation, MESSAGING$ } from '../../../../relay/environment';
import { resolveHasUserChoiceParsedCsvMapper } from '../../../../utils/csvMapperUtils';
import { FieldOption, fieldSpacingContainerStyle } from '../../../../utils/field';
import { KNOWLEDGE_KNASKIMPORT, KNOWLEDGE_KNUPLOAD } from '../../../../utils/hooks/useGranted';
import Security from '../../../../utils/Security';
import { TEN_SECONDS } from '../../../../utils/Time';
import { FileLine_file$data } from '../../common/files/__generated__/FileLine_file.graphql';
import FileLine from '../../common/files/FileLine';
import { fileManagerAskJobImportMutation } from '../../common/files/FileManager';
import { scopesConn } from '../../common/stix_core_objects/StixCoreObjectFilesAndHistory';
import { ExternalReferenceFileImportViewer_entity$data } from './__generated__/ExternalReferenceFileImportViewer_entity.graphql';

const interval$ = interval(TEN_SECONDS);

interface ConnectorConfiguration {
  configuration: string;
  id: string;
  name: string;
}
interface Connector {
  id: string;
  name: string;
  active: boolean;
  only_contextual: boolean;
  connector_scope: string[];
  updated_at: string;
  configurations: ConnectorConfiguration[];
}

const importValidation = (t: (value: string) => string, configurations: boolean) => {
  const shape = {
    connector_id: Yup.string().required(t('This field is required')),
  };
  if (configurations) {
    return Yup.object().shape({
      ...shape,
      configuration: Yup.string().required(t('This field is required')),
      objectMarking: Yup.array().required(t('This field is required')),
    });
  }
  return Yup.object().shape(shape);
};

interface ExternalReferenceFileImportViewerBaseProps {
  externalReference: ExternalReferenceFileImportViewer_entity$data;
  disableImport: boolean;
  connectors: Record<
    string,
    {
      id: string;
      name: string;
      active: boolean;
      connector_scope: string[];
      updated_at: string;
    }
  >;
  relay: RelayRefetchProp;
  connectorsImport: Connector[];
}
const ExternalReferenceFileImportViewerBase: FunctionComponent<
  ExternalReferenceFileImportViewerBaseProps
> = ({ externalReference, disableImport, relay, connectorsImport }) => {
  const { t_i18n } = useFormatter();
  const [fileToImport, setFileToImport] = useState<
    FileLine_file$data | null | undefined
  >(null);

  const [selectedConnector, setSelectedConnector] = useState<Connector | null>(null);
  const { id, importFiles } = externalReference;
  const importConnsPerFormat = scopesConn(connectorsImport);
  const handleOpenImport = (file: FileLine_file$data | null | undefined) => setFileToImport(file);
  const handleCloseImport = () => setFileToImport(null);
  const onSubmitImport: FormikConfig<{ connector_id: string; configuration: string; objectMarking: FieldOption[] }>['onSubmit'] = (
    values,
    { setSubmitting, resetForm },
  ) => {
    const variables: FileManagerAskJobImportMutation$variables = {
      fileName: fileToImport?.id ?? '',
      connectorId: values.connector_id,
    };
    if (selectedConnector?.name === 'ImportCsv') {
      const markings = values.objectMarking.map((option) => option.value);
      const parsedConfig = JSON.parse(values.configuration);
      if (typeof parsedConfig === 'object') {
        parsedConfig.markings = [...markings];
        variables.configuration = JSON.stringify(parsedConfig);
      }
    }

    commitMutation({
      mutation: fileManagerAskJobImportMutation,
      variables,
      onCompleted: () => {
        setSubmitting(false);
        resetForm();
        handleCloseImport();
        MESSAGING$.notifySuccess('Import successfully asked');
      },
      updater: undefined,
      optimisticUpdater: undefined,
      optimisticResponse: undefined,
      onError: undefined,
      setSubmitting: undefined,
    });
  };
  useEffect(() => {
    // Refresh the export viewer every interval
    const subscription = interval$.subscribe(() => {
      if (relay.refetch) {
        relay.refetch({ id });
      }
    });
    return function cleanup() {
      subscription.unsubscribe();
    };
  }, []);
  const fileToImportBoolean = () => {
    return !!fileToImport;
  };
  const connectors = connectorsImport.filter((n) => !n.only_contextual);

  const handleSelectConnector = (_: string, value: string) => {
    setSelectedConnector(connectors?.find((c) => c.id === value) ?? null);
  };

  const invalidCsvMapper = selectedConnector?.name === 'ImportCsv'
    && selectedConnector?.configurations?.length === 0;
  const [hasUserChoiceCsvMapper, setHasUserChoiceCsvMapper] = useState(false);
  const onCsvMapperSelection = (option: string | CsvMapperFieldOption) => {
    if (selectedConnector?.name === 'ImportCsv') {
      const parsedOption = typeof option === 'string' ? JSON.parse(option) : option;
      const parsedRepresentations = JSON.parse(parsedOption.representations);
      const selectedCsvMapper = {
        ...parsedOption,
        representations: [...parsedRepresentations],
      };
      const hasUserChoiceCsvMapperRepresentations = resolveHasUserChoiceParsedCsvMapper(selectedCsvMapper);
      setHasUserChoiceCsvMapper(hasUserChoiceCsvMapperRepresentations);
    }
  };
  return (
    <React.Fragment>
      <div style={{ height: '100%' }} className="break">
        <Card
          title={t_i18n('Uploaded files')}
          action={(
            <Security needs={[KNOWLEDGE_KNUPLOAD]} capabilitiesInDraft={[KNOWLEDGE_KNASKIMPORT]}>
              <UploadImport
                size="small"
                fontSize="small"
                entityId={id}
                onSuccess={() => {
                  if (relay.refetch) {
                    relay.refetch({ id });
                  }
                }}
              />
            </Security>
          )}
        >
          {importFiles?.edges?.length ? (
            <List>
              {importFiles?.edges?.map(
                (
                  file: {
                    node: {
                      id: string;
                      metaData: {
                        mimetype: string | null | undefined;
                      } | null | undefined;
                      ' $fragmentSpreads': FragmentRefs<'FileLine_file'>;
                    };
                  } | null | undefined,
                ) => file?.node && (
                  <FileLine
                    key={file.node.id}
                    dense={true}
                    disableImport={disableImport}
                    file={file.node}
                    connectors={
                      importConnsPerFormat[file.node.metaData?.mimetype ?? 0]
                    }
                    handleOpenImport={handleOpenImport}
                  />
                ),
              )}
            </List>
          ) : (
            <div style={{ display: 'table', height: '100%', width: '100%' }}>
              <span
                style={{
                  display: 'table-cell',
                  verticalAlign: 'middle',
                  textAlign: 'center',
                }}
              >
                {t_i18n('No file for the moment')}
              </span>
            </div>
          )}
        </Card>
      </div>
      <div>
        <Formik
          enableReinitialize={true}
          initialValues={{ connector_id: '', configuration: '', objectMarking: [] as FieldOption[] }}
          validationSchema={importValidation(t_i18n, (selectedConnector?.configurations?.length ?? 0) > 0)}
          onSubmit={onSubmitImport}
          onReset={handleCloseImport}
        >
          {({ submitForm, handleReset, isSubmitting, setFieldValue, isValid }) => (
            <Form>
              <Dialog
                open={fileToImportBoolean()}
                onClose={() => handleReset()}
                title={t_i18n('Launch an import')}
              >
                <Field
                  component={SelectField}
                  name="connector_id"
                  label={t_i18n('Connector')}
                  fullWidth={true}
                  containerstyle={{ width: '100%' }}
                  onChange={handleSelectConnector}
                >
                  {connectorsImport.map((connector, i: number) => {
                    const disabled = !fileToImport
                      || (connector.connector_scope.length > 0
                        && !includes(
                          fileToImport.metaData?.mimetype,
                          connector.connector_scope,
                        ));
                    return (
                      <MenuItem
                        key={i}
                        value={connector.id}
                        disabled={disabled || !connector.active}
                      >
                        {connector.name}
                      </MenuItem>
                    );
                  })}
                </Field>
                {(selectedConnector?.configurations?.length ?? 0) > 0
                  ? (
                      <Field
                        component={SelectField}
                        variant="standard"
                        name="configuration"
                        label={t_i18n('Configuration')}
                        fullWidth={true}
                        containerstyle={{ marginTop: 20, width: '100%' }}
                        onChange={(_: string, value: CsvMapperFieldOption) => onCsvMapperSelection(value)}
                      >
                        {selectedConnector?.configurations.map((config) => {
                          return (
                            <MenuItem
                              key={config.id}
                              value={config.configuration}
                            >
                              {config.name}
                            </MenuItem>
                          );
                        })}
                      </Field>
                    ) : <ManageImportConnectorMessage name={selectedConnector?.name} />
                }
                {selectedConnector?.name === 'ImportCsv'
                  && hasUserChoiceCsvMapper
                  && (
                    <>
                      <ObjectMarkingField
                        name="objectMarking"
                        style={fieldSpacingContainerStyle}
                        setFieldValue={setFieldValue}
                      />
                    </>
                  )
                }
                <DialogActions>
                  <Button variant="secondary" onClick={handleReset} disabled={isSubmitting}>
                    {t_i18n('Cancel')}
                  </Button>
                  <Button
                    onClick={submitForm}
                    disabled={isSubmitting || !isValid || invalidCsvMapper || !selectedConnector}
                  >
                    {t_i18n('Create')}
                  </Button>
                </DialogActions>
              </Dialog>
            </Form>
          )}
        </Formik>
      </div>
    </React.Fragment>
  );
};

const ExternalReferenceFileImportViewerComponent = compose(inject18n)(
  ExternalReferenceFileImportViewerBase,
);

const ExternalReferenceFileImportViewerRefetchQuery = graphql`
  query ExternalReferenceFileImportViewerRefetchQuery($id: String!) {
    externalReference(id: $id) {
      ...ExternalReferenceFileImportViewer_entity
    }
  }
`;

const ExternalReferenceFileImportViewer = createRefetchContainer(
  ExternalReferenceFileImportViewerComponent,
  {
    externalReference: graphql`
      fragment ExternalReferenceFileImportViewer_entity on ExternalReference {
        id
        entity_type
        importFiles(first: 500) @connection(key: "Pagination_importFiles") {
          edges {
            node {
              id
              ...FileLine_file
              metaData {
                mimetype
              }
            }
          }
        }
      }
    `,
    connectorsImport: graphql`
      fragment ExternalReferenceFileImportViewer_connectorsImport on Connector
      @relay(plural: true) {
        id
        name
        active
        connector_scope
        only_contextual
        updated_at
        configurations {
            id
            name,
            configuration
        }
      }
    `,
  },
  ExternalReferenceFileImportViewerRefetchQuery,
);

export default ExternalReferenceFileImportViewer;
