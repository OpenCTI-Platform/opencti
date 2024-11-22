import React, { FC, useState } from 'react';
import { graphql, PreloadedQuery, usePreloadedQuery } from 'react-relay';
import { createSearchParams, useNavigate } from 'react-router-dom';
import { FormikHelpers } from 'formik/dist/types';
import { FileManagerExportMutation } from '@components/common/files/__generated__/FileManagerExportMutation.graphql';
import { StixCoreObjectFileExportQuery } from '@components/common/stix_core_objects/__generated__/StixCoreObjectFileExportQuery.graphql';
import StixCoreObjectFileExportForm, {
  ConnectorOption,
  StixCoreObjectFileExportFormInputs,
  StixCoreObjectFileExportFormProps,
} from '@components/common/form/StixCoreObjectFileExportForm';
import {
  StixCoreObjectContentFilesUploadStixCoreObjectMutation,
  StixCoreObjectContentFilesUploadStixCoreObjectMutation$variables,
} from '@components/common/stix_core_objects/__generated__/StixCoreObjectContentFilesUploadStixCoreObjectMutation.graphql';
import { stixCoreObjectContentFilesUploadStixCoreObjectMutation } from '@components/common/stix_core_objects/StixCoreObjectContentFiles';
import axios from 'axios';
import { fileManagerExportMutation } from '../files/FileManager';
import useQueryLoading from '../../../../utils/hooks/useQueryLoading';
import { useFormatter } from '../../../../components/i18n';
import { APP_BASE_PATH, handleErrorInForm, MESSAGING$ } from '../../../../relay/environment';
import { resolveLink } from '../../../../utils/Entity';
import useApiMutation from '../../../../utils/hooks/useApiMutation';
import { htmlToPdfReport } from '../../../../utils/htmlToPdf';
import useFileFromTemplate from '../../../../utils/outcome_template/engine/useFileFromTemplate';

export const BUILT_IN_FROM_FILE_TEMPLATE = {
  value: 'fromFileTemplate',
  connectorScope: ['application/pdf'],
};
export const BUILT_IN_FROM_TEMPLATE = {
  value: 'fromTemplate',
  connectorScope: ['text/html', 'application/pdf'],
};

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

interface OpenComponentProps {
  onOpen: () => void
  isExportPossible: boolean
}

type StixCoreObjectFileExportComponentProps = {
  connectorsQueryRef: PreloadedQuery<StixCoreObjectFileExportQuery>;
  OpenFormComponent: FC<OpenComponentProps>;
  scoId: string;
  scoEntityType: string;
  scoName?: string;
  redirectToContentTab?: boolean;
  onClose?: () => void
} & Pick<StixCoreObjectFileExportFormProps, 'templates' | 'filesFromTemplate' | 'defaultValues'>;

const StixCoreObjectFileExportComponent = ({
  connectorsQueryRef,
  OpenFormComponent,
  scoId,
  scoEntityType,
  scoName,
  redirectToContentTab,
  filesFromTemplate,
  templates,
  defaultValues,
  onClose,
}: StixCoreObjectFileExportComponentProps) => {
  const navigate = useNavigate();
  const { t_i18n } = useFormatter();
  const [isOpen, setOpen] = useState(false);
  const { buildFileFromTemplate } = useFileFromTemplate();

  const { connectorsForExport } = usePreloadedQuery<StixCoreObjectFileExportQuery>(
    stixCoreObjectFileExportQuery,
    connectorsQueryRef,
  );
  // Keep only active connectors.
  const activeConnectors: ConnectorOption[] = (connectorsForExport ?? [])
    .flatMap((c) => (c?.active ? {
      value: c.id,
      label: c.name,
      connectorScope: c.connector_scope ?? [],
    } : []));
  // Add "built-in" connectors to the list.
  if (filesFromTemplate && filesFromTemplate.length > 0) {
    activeConnectors.push({
      ...BUILT_IN_FROM_FILE_TEMPLATE,
      label: t_i18n('Built-in: HTML template to PDF'),
    });
  }
  if (templates && templates.length > 0) {
    activeConnectors.push({
      ...BUILT_IN_FROM_TEMPLATE,
      label: t_i18n('Built-in: template to HTML/PDF'),
    });
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
    if (!values.templateFile && !values.template) {
      throw Error(t_i18n('Invalid form to export a template'));
    }

    const { setSubmitting } = helpers;
    const uploadFile = (variables: StixCoreObjectContentFilesUploadStixCoreObjectMutation$variables) => {
      commitUploadFile({
        variables,
        onCompleted: () => {
          setSubmitting(false);
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
          templateId,
          maxContentMarkings,
        );

        if (values.format === 'text/html') {
          // Export template into HTML file.
          const fileName = `${values.template.label}.html`;
          const blob = new Blob([templateContent], { type: 'text/html' });
          const file = new File([blob], fileName, { type: blob.type });
          uploadFile({
            id: scoId,
            fileMarkings,
            fromTemplate: true,
            file,
          });
        } else {
          // Export template directly in PDF without HTML step.
          const templateName = values.template.label;
          const fileName = `${templateName}_${new Date().toISOString()}.pdf`;
          const PDF = htmlToPdfReport(scoName ?? '', templateContent, templateName, fileMarkings);
          PDF.getBlob((blob) => {
            uploadFile({
              id: scoId,
              fileMarkings,
              file: new File([blob], fileName, { type: blob.type }),
            });
          });
        }
      } else if (values.templateFile !== null) {
        const templateMarkings = values.templateFile.fileMarkings.map((m) => m.name);
        const fileMarkings = values.templateFile.fileMarkings.map((m) => m.id);
        const templateId = values.templateFile.value;
        const url = `${APP_BASE_PATH}/storage/view/${encodeURIComponent(templateId)}`;
        const templateFile = await axios.get(url);
        const templateName = (templateId.split('/').pop() ?? '').split('.')[0];
        const fileName = `${templateName}_${new Date().toISOString()}.pdf`;
        const PDF = htmlToPdfReport(scoName ?? '', templateFile.data, templateName, templateMarkings);
        PDF.getBlob((blob) => {
          uploadFile({
            id: scoId,
            fileMarkings,
            file: new File([blob], fileName, { type: blob.type }),
          });
        });
      }
    } catch (e) {
      MESSAGING$.notifyError(t_i18n('Error trying to export a PDF template'));
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
    const { setSubmitting, setErrors } = helpers;
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
      BUILT_IN_FROM_FILE_TEMPLATE.value,
    ].includes(values.connector?.value ?? '');
    if (isBuiltInConnector) {
      await submitExportBuiltIn(values, helpers);
    } else {
      await submitExportConnector(values, helpers);
    }
  };

  return (
    <>
      <OpenFormComponent
        onOpen={() => setOpen(true)}
        isExportPossible={activeConnectors.length > 0}
      />
      <StixCoreObjectFileExportForm
        connectors={activeConnectors}
        filesFromTemplate={filesFromTemplate}
        templates={templates}
        isOpen={isOpen}
        onSubmit={onSubmitExport}
        onClose={close}
        defaultValues={defaultValues}
      />
    </>
  );
};

export type StixCoreObjectFileExportProps = Omit<StixCoreObjectFileExportComponentProps, 'connectorsQueryRef'>;

const StixCoreObjectFileExport = (props: StixCoreObjectFileExportProps) => {
  const connectorsQueryRef = useQueryLoading<StixCoreObjectFileExportQuery>(
    stixCoreObjectFileExportQuery,
  );

  return (
    <>
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
