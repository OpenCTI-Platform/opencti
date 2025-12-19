import React, { FC, useState } from 'react';
import { graphql, PreloadedQuery, usePreloadedQuery } from 'react-relay';
import { createSearchParams, useNavigate } from 'react-router-dom';
import { FormikHelpers } from 'formik/dist/types';
import { FileManagerExportMutation } from '@components/common/files/__generated__/FileManagerExportMutation.graphql';
import { StixCoreObjectFileExportQuery } from '@components/common/stix_core_objects/__generated__/StixCoreObjectFileExportQuery.graphql';
import StixCoreObjectFileExportForm, {
  ConnectorOption,
  FileOption,
  StixCoreObjectFileExportFormInputs,
  StixCoreObjectFileExportFormProps,
} from '@components/common/form/StixCoreObjectFileExportForm';
import {
  StixCoreObjectContentFilesUploadStixCoreObjectMutation,
  StixCoreObjectContentFilesUploadStixCoreObjectMutation$variables,
} from '@components/common/stix_core_objects/__generated__/StixCoreObjectContentFilesUploadStixCoreObjectMutation.graphql';
import { stixCoreObjectContentFilesUploadStixCoreObjectMutation } from '@components/common/stix_core_objects/StixCoreObjectContentFiles';
import axios from 'axios';
import StixCoreObjectAskAI from '@components/common/stix_core_objects/StixCoreObjectAskAI';
import { fileManagerExportMutation } from '../files/FileManager';
import useQueryLoading from '../../../../utils/hooks/useQueryLoading';
import { useFormatter } from '../../../../components/i18n';
import { APP_BASE_PATH, handleErrorInForm, MESSAGING$ } from '../../../../relay/environment';
import { resolveLink } from '../../../../utils/Entity';
import useApiMutation from '../../../../utils/hooks/useApiMutation';
import { htmlToPdf, htmlToPdfReport } from '../../../../utils/htmlToPdf/htmlToPdf';
import useFileFromTemplate from '../../../../utils/outcome_template/engine/useFileFromTemplate';
import { getMainRepresentative } from '../../../../utils/defaultRepresentatives';
import useGranted, { KNOWLEDGE_KNGETEXPORT, KNOWLEDGE_KNUPLOAD } from '../../../../utils/hooks/useGranted';
import { FieldOption } from '../../../../utils/field';

export const BUILT_IN_HTML_TO_PDF = {
  value: 'builtInHtmlToPdf',
  connectorScope: ['application/pdf'],
};
export const BUILT_IN_FROM_TEMPLATE = {
  value: 'fromTemplate',
  connectorScope: ['text/html', 'application/pdf'],
};

const stixCoreObjectFileExportQuery = graphql`
  query StixCoreObjectFileExportQuery($id: String!) {
    stixCoreObject(id: $id) {
      id
      entity_type
      representative {
        main
      }
      objectMarking {
        id
        representative {
          main
        }
      }
      importFiles {
        edges {
          node {
            id
            name
            metaData {
              mimetype
            }
            objectMarking {
              id
              representative {
                main
              }
            }
          }
        }
      }
      exportFiles {
        edges {
          node {
            id
            name
            metaData {
              mimetype
            }
            objectMarking {
              id
              representative {
                main
              }
            }
          }
        }
      }
      ... on Container {
        fintelTemplates {
          id
          name
        }
        filesFromTemplate(first: 500) {
          edges {
            node {
              id
              name
              metaData {
                mimetype
              }
              objectMarking {
                id
                representative {
                  main
                }
              }
            }
          }
        }
      }
      ... on Report {
        content
      }
      ... on Case {
        content
      }
      ... on Grouping {
        content
      }
    }
    connectorsForExport {
      id
      name
      active
      connector_scope
      updated_at
    }
  }
`;

interface OpenComponentProps {
  onOpen: () => void;
  isExportPossible: boolean;
}

type StixCoreObjectFileExportComponentProps = {
  connectorsQueryRef: PreloadedQuery<StixCoreObjectFileExportQuery>;
  OpenFormComponent: FC<OpenComponentProps>;
  scoId: string;
  scoEntityType: string;
  scoName?: string;
  redirectToContentTab?: boolean;
  onClose?: () => void;
  onExportCompleted?: (fileName?: string, isDeleted?: boolean) => void;
} & Pick<StixCoreObjectFileExportFormProps, 'defaultValues'>;

const StixCoreObjectFileExportComponent = ({
  connectorsQueryRef,
  OpenFormComponent,
  scoId,
  scoEntityType,
  scoName,
  redirectToContentTab,
  defaultValues,
  onClose,
  onExportCompleted,
}: StixCoreObjectFileExportComponentProps) => {
  const navigate = useNavigate();
  const { t_i18n } = useFormatter();
  const [isOpen, setOpen] = useState(false);
  const [askAiOpen, setAskAiOpen] = useState(false);
  const handleOpenAskAi = () => {
    setAskAiOpen(true);
    setOpen(false);
  };
  const handleCloseAskAi = () => {
    setAskAiOpen(false);
  };
  const { buildFileFromTemplate } = useFileFromTemplate();
  const hasUploadAndExportCapabilities = useGranted([KNOWLEDGE_KNUPLOAD, KNOWLEDGE_KNGETEXPORT], true);

  const {
    connectorsForExport,
    stixCoreObject,
  } = usePreloadedQuery<StixCoreObjectFileExportQuery>(
    stixCoreObjectFileExportQuery,
    connectorsQueryRef,
  );

  // Keep only markdown and html files
  const files = [
    ...(stixCoreObject?.importFiles?.edges ?? []),
    ...(stixCoreObject?.exportFiles?.edges ?? []),
    ...(stixCoreObject?.filesFromTemplate?.edges ?? []),
  ];
  const fileOptions: FileOption[] = files.flatMap((e) => {
    if (!e.node || !['text/html', 'text/markdown'].includes(e.node.metaData?.mimetype ?? '')) {
      return [];
    }
    return {
      value: e.node.id,
      label: getMainRepresentative(e.node),
      fileMarkings: e.node.objectMarking.map((o) => ({
        id: o.id,
        name: getMainRepresentative(o),
      })),
    };
  });
  // Artificially add mappable content in possible exports
  fileOptions.push({
    value: 'mappableContent',
    label: t_i18n('Mappable main content'),
    fileMarkings: (stixCoreObject?.objectMarking ?? []).map((o) => ({
      id: o.id,
      name: getMainRepresentative(o),
    })),
  });

  const templateOptions: FieldOption[] = (stixCoreObject?.fintelTemplates ?? []).map((t) => ({
    value: t.id,
    label: t.name,
  }));

  // Keep only active connectors.
  const activeConnectors: ConnectorOption[] = (connectorsForExport ?? [])
    .flatMap((c) => (c?.active ? {
      value: c.id,
      label: c.name,
      connectorScope: c.connector_scope ?? [],
    } : []));
  // Add "built-in" connectors to the list if the user has the Export and the Upload capabilities
  if (hasUploadAndExportCapabilities) {
    if (fileOptions.length > 0) {
      activeConnectors.push({
        ...BUILT_IN_HTML_TO_PDF,
        label: t_i18n('HTML content files to PDF'),
      });
    }
    if (templateOptions.length > 0) {
      activeConnectors.push({
        ...BUILT_IN_FROM_TEMPLATE,
        label: t_i18n('Generate FINTEL from template'),
      });
    }
  }

  const close = () => {
    setOpen(false);
    onClose?.();
  };

  const [commitExport] = useApiMutation<FileManagerExportMutation>(
    fileManagerExportMutation,
  );
  const [commitUploadFile] = useApiMutation<StixCoreObjectContentFilesUploadStixCoreObjectMutation>(
    stixCoreObjectContentFilesUploadStixCoreObjectMutation,
  );

  /**
   * Export using "built-in" connector.
   *
   * @param values Form filled values.
   * @param helpers Formik helpers to manage form.
   */
  const submitExportBuiltIn: typeof onSubmitExport = async (values, helpers) => {
    if ((!values.fileToExport && !values.template) || !values.exportFileName) {
      throw Error(t_i18n('Invalid form to export a template'));
    }
    const { setSubmitting, resetForm } = helpers;
    const uploadFile = (variables: StixCoreObjectContentFilesUploadStixCoreObjectMutation$variables) => {
      commitUploadFile({
        variables,
        onCompleted: (result) => {
          setSubmitting(false);
          if (result.stixCoreObjectEdit?.importPush) {
            onExportCompleted?.(result.stixCoreObjectEdit.importPush.id);
          }
          resetForm();
          close();
        },
        onError: () => {
          resetForm();
          close();
        },
      });
    };

    try {
      if (values.template !== null) {
        const templateId = values.template.value;
        const fileMarkings = values.fileMarkings.map(({ value }) => value);
        const maxContentMarkings = values.contentMaxMarkings.map(({ value }) => value);
        const templateContent = await buildFileFromTemplate(
          scoId,
          maxContentMarkings,
          templateId,
        );

        if (values.format === 'text/html') {
          // Export fintel template into HTML file.
          const fileName = `${values.exportFileName}.html`;
          const blob = new Blob([templateContent], { type: 'text/html' });
          const file = new File([blob], fileName, { type: blob.type });
          uploadFile({
            id: scoId,
            fileMarkings,
            fromTemplate: true,
            file,
          });
        } else {
          // Export fintel template directly in PDF without HTML step.
          const templateName = values.template.label;
          const fileName = `${values.exportFileName}.pdf`;
          const fileMarkingNames = values.fileMarkings.map(({ label }) => label);
          const PDF = await htmlToPdfReport(scoName ?? '', templateContent, templateName, fileMarkingNames, values.fintelDesign?.value);
          PDF.getBlob((blob) => {
            uploadFile({
              id: scoId,
              fileMarkings,
              file: new File([blob], fileName, { type: blob.type }),
              fromTemplate: true,
            });
          });
        }
      } else if (values.fileToExport !== null) {
        const fileMarkings = values.fileMarkings.map((m) => m.value);
        const fileMarkingNames = values.fileMarkings.map((m) => m.label);
        const fileId = values.fileToExport.value;
        let fileData: string;
        if (fileId === 'mappableContent') {
          fileData = stixCoreObject?.content ?? '';
        } else {
          const url = `${APP_BASE_PATH}/storage/view/${encodeURIComponent(fileId)}`;
          const fileResponse = await axios.get(url);
          fileData = fileResponse.data;
        }
        const name = (fileId.split('/').pop() ?? '').split('.')[0];
        const fileName = `${values.exportFileName}.pdf`;
        const isFromTemplate = fileId.startsWith('fromTemplate');
        const PDF = isFromTemplate
          ? await htmlToPdfReport(scoName ?? '', fileData, name, fileMarkingNames, values.fintelDesign?.value)
          : htmlToPdf(fileId, fileData);
        PDF.getBlob((blob) => {
          uploadFile({
            id: scoId,
            fileMarkings,
            file: new File([blob], fileName, { type: blob.type }),
            fromTemplate: isFromTemplate,
          });
        });
      }
    } catch (e) {
      MESSAGING$.notifyError(t_i18n('Error trying to export the file'));
      throw e;
    }
  };

  /**
   * Classic connector export.
   *
   * @param values Form filled values.
   * @param helpers Formik helpers to manage form.
   */
  const submitExportConnector: typeof onSubmitExport = async (values, helpers) => {
    if (!values.type) return;
    const { setSubmitting, setErrors, resetForm } = helpers;
    const contentMaxMarkings = values.contentMaxMarkings.map(({ value }) => value);
    const fileMarkings = values.fileMarkings.map(({ value }) => value);
    commitExport({
      variables: {
        id: scoId,
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
        resetForm();
        close();
        setSubmitting(false);
        const fileId = exportData.stixCoreObjectEdit?.exportAsk?.[0].id;
        const redirectTab = values.format === 'application/pdf' && redirectToContentTab ? 'content' : 'files';
        MESSAGING$.notifySuccess('Export successfully started');
        navigate({
          pathname: `${resolveLink(scoEntityType)}/${scoId}/${redirectTab}`,
          search: fileId ? `?${createSearchParams({ currentFileId: fileId })}` : '',
        });
      },
    });
  };

  const onSubmitExport = async (
    values: StixCoreObjectFileExportFormInputs,
    helpers: FormikHelpers<StixCoreObjectFileExportFormInputs>,
  ) => {
    const isBuiltInConnector = [
      BUILT_IN_FROM_TEMPLATE.value,
      BUILT_IN_HTML_TO_PDF.value,
    ].includes(values.connector?.value ?? '');
    if (isBuiltInConnector) {
      await submitExportBuiltIn(values, helpers);
    } else {
      await submitExportConnector(values, helpers);
    }
  };
  const isContainer = ['Report', 'Case-Incident', 'Case-RFI'].includes(stixCoreObject?.entity_type ?? 'Unknown');

  return (
    <>
      <OpenFormComponent
        onOpen={() => setOpen(true)}
        isExportPossible={activeConnectors.length > 0}
      />
      {isOpen && (
        <StixCoreObjectFileExportForm
          connectors={activeConnectors}
          fileOptions={fileOptions}
          templates={templateOptions}
          isOpen={isOpen}
          onSubmit={onSubmitExport}
          onClose={close}
          defaultValues={defaultValues}
          scoName={scoName}
          instanceType={stixCoreObject?.entity_type}
          handleOpenAskAi={handleOpenAskAi}
        />
      )}
      {stixCoreObject && isContainer && (
        <StixCoreObjectAskAI
          instanceId={stixCoreObject.id}
          instanceName={stixCoreObject.representative.main}
          instanceType={stixCoreObject.entity_type}
          type="container"
          optionsOpen={askAiOpen}
          handleCloseOptions={handleCloseAskAi}
        />
      )}
    </>
  );
};

export type StixCoreObjectFileExportProps = Omit<StixCoreObjectFileExportComponentProps, 'connectorsQueryRef'>;

const StixCoreObjectFileExport = (props: StixCoreObjectFileExportProps) => {
  const { OpenFormComponent, scoId } = props;
  const connectorsQueryRef = useQueryLoading<StixCoreObjectFileExportQuery>(
    stixCoreObjectFileExportQuery,
    { id: scoId },
  );
  return (
    <>
      {!connectorsQueryRef && (
        <OpenFormComponent onOpen={() => {}} isExportPossible={false} />
      )}
      {connectorsQueryRef && (
        <React.Suspense>
          <StixCoreObjectFileExportComponent
            connectorsQueryRef={connectorsQueryRef}
            {...props}
          />
        </React.Suspense>
      )}
    </>
  );
};

export default StixCoreObjectFileExport;
