import React, { FunctionComponent, ReactNode, useState } from 'react';
import List from '@mui/material/List';
import ListItemText from '@mui/material/ListItemText';
import Drawer from '@mui/material/Drawer';
import ListItemIcon from '@mui/material/ListItemIcon';
import { FileOutline } from 'mdi-material-ui';
import IconButton from '@mui/material/IconButton';
import Tooltip from '@mui/material/Tooltip';
import { AddOutlined } from '@mui/icons-material';
import { graphql } from 'react-relay';
import ListItemButton from '@mui/material/ListItemButton';
import Typography from '@mui/material/Typography';
import EEChip from '@components/common/entreprise_edition/EEChip';
import { StixCoreObjectContent_stixCoreObject$data } from '@components/common/stix_core_objects/__generated__/StixCoreObjectContent_stixCoreObject.graphql';
import { FormikConfig } from 'formik/dist/types';
import ContentTemplateForm, { ContentTemplateFormInputs } from '@components/common/form/ContentTemplateForm';
import {
  StixCoreObjectContentFilesUploadStixCoreObjectMutation,
} from '@components/common/stix_core_objects/__generated__/StixCoreObjectContentFilesUploadStixCoreObjectMutation.graphql';
import CreateFileForm, { CreateFileFormInputs } from '@components/common/form/CreateFileForm';
import StixCoreObjectContentFilesList from '@components/common/stix_core_objects/StixCoreObjectContentFilesList';
import { useSettingsMessagesBannerHeight } from '@components/settings/settings_messages/SettingsMessagesBanner';
import { useFormatter } from '../../../../components/i18n';
import FileUploader from '../files/FileUploader';
import useContentFromTemplate from '../../../../utils/outcome_template/engine/useContentFromTemplate';
import useEnterpriseEdition from '../../../../utils/hooks/useEnterpriseEdition';
import { isNilField } from '../../../../utils/utils';
import useHelper from '../../../../utils/hooks/useHelper';
import useApiMutation from '../../../../utils/hooks/useApiMutation';
import type { Template } from '../../../../utils/outcome_template/template';
import { MESSAGING$ } from '../../../../relay/environment';
import { KNOWLEDGE_KNUPLOAD } from '../../../../utils/hooks/useGranted';
import Security from '../../../../utils/Security';

interface ContentBlocProps {
  title: ReactNode
  children: ReactNode
  actions?: ReactNode
}

const ContentBloc = ({ title, actions, children }:ContentBlocProps) => {
  return (
    <div style={{ marginBottom: '24px' }}>
      <div style={{ padding: '0 16px', display: 'flex', alignItems: 'center' }}>
        <Typography variant="body2" style={{ display: 'flex', alignItems: 'center', flex: 1 }}>
          {title}
        </Typography>
        <div>{actions}</div>
      </div>
      {children}
    </div>
  );
};

export const stixCoreObjectContentFilesUploadStixCoreObjectMutation = graphql`
  mutation StixCoreObjectContentFilesUploadStixCoreObjectMutation(
    $id: ID!
    $file: Upload!
    $fileMarkings: [String]
    $noTriggerImport: Boolean
    $fromTemplate: Boolean
  ) {
    stixCoreObjectEdit(id: $id) {
      importPush(file: $file, noTriggerImport: $noTriggerImport, fileMarkings: $fileMarkings, fromTemplate: $fromTemplate) {
        id
        name
        uploadStatus
        lastModified
        lastModifiedSinceMin
        metaData {
          mimetype
          list_filters
          messages {
            timestamp
            message
          }
          errors {
            timestamp
            message
          }
        }
      }
    }
  }
`;

interface StixCoreObjectContentFilesProps {
  files: NonNullable<StixCoreObjectContent_stixCoreObject$data['importFiles']>['edges'][number]['node'][],
  stixCoreObjectId: string,
  stixCoreObjectName: string,
  content: string | null,
  handleSelectFile: (fileId: string) => void,
  handleSelectContent: () => void,
  contentSelected: boolean,
  currentFileId: string,
  onFileChange: (fileName?: string, isDeleted?: boolean) => void,
  exportFiles: NonNullable<StixCoreObjectContent_stixCoreObject$data['exportFiles']>['edges'][number]['node'][],
  contentsFromTemplate: NonNullable<StixCoreObjectContent_stixCoreObject$data['contentsFromTemplate']>['edges'][number]['node'][],
  hasOutcomesTemplate?: boolean,
  templates: Template[],
}

const StixCoreObjectContentFiles: FunctionComponent<StixCoreObjectContentFilesProps> = ({
  files,
  stixCoreObjectId,
  stixCoreObjectName,
  content,
  handleSelectFile,
  handleSelectContent,
  contentSelected,
  currentFileId,
  onFileChange,
  exportFiles,
  contentsFromTemplate,
  hasOutcomesTemplate,
  templates,
}) => {
  const { t_i18n } = useFormatter();
  const { buildContentFromTemplate } = useContentFromTemplate();
  const isEnterpriseEdition = useEnterpriseEdition();
  const { isFeatureEnable } = useHelper();
  const isContentFromTemplateEnabled = isFeatureEnable('CONTENT_FROM_TEMPLATE');
  const settingsMessagesBannerHeight = useSettingsMessagesBannerHeight();

  const [commitUploadFile] = useApiMutation<StixCoreObjectContentFilesUploadStixCoreObjectMutation>(
    stixCoreObjectContentFilesUploadStixCoreObjectMutation,
  );

  const [displayCreate, setDisplayCreate] = useState(false);
  const [displayCreateContentFromTemplate, setDisplayCreateContentFromTemplate] = useState(false);

  const handleOpenCreate = () => {
    setDisplayCreate(true);
  };

  const handleOpenCreateContentFromTemplate = () => {
    setDisplayCreateContentFromTemplate(true);
  };

  const handleCloseCreate = () => {
    setDisplayCreate(false);
  };

  const handleCloseCreateContentFromTemplate = () => {
    setDisplayCreateContentFromTemplate(false);
  };

  const onSubmit: FormikConfig<CreateFileFormInputs>['onSubmit'] = (
    values,
    { setSubmitting, resetForm },
  ) => {
    const { name, type } = values;
    let fileName = name;
    if (type === 'text/plain' && !name.endsWith('.txt')) {
      fileName += '.txt';
    } else if (type === 'text/html' && !name.endsWith('.html')) {
      fileName += '.html';
    } else if (type === 'text/markdown' && !name.endsWith('.md')) {
      fileName += '.md';
    }

    const blob = new Blob([t_i18n('Write something awesome...')], { type });
    const file = new File([blob], fileName, { type });
    const fileMarkings = values.fileMarkings.map(({ value }) => value);

    commitUploadFile({
      variables: { file, id: stixCoreObjectId, fileMarkings },
      onCompleted: (result) => {
        setSubmitting(false);
        resetForm();
        handleCloseCreate();
        if (result.stixCoreObjectEdit?.importPush) {
          onFileChange(result.stixCoreObjectEdit.importPush.id);
        }
      },
    });
  };

  const onSubmitContentFromTemplate: FormikConfig<ContentTemplateFormInputs>['onSubmit'] = async (
    values,
    { setSubmitting, resetForm },
  ) => {
    const { name, type } = values;
    let fileName = name;
    if (type === 'text/html' && !name.endsWith('.html')) {
      fileName += '.html';
    }

    const fileMarkings = values.fileMarkings.map(({ value }) => value);
    const maxContentMarkings = (values.maxMarkings ?? []).map(({ value }) => value);
    const templateId = values.template?.value;

    if (!templateId) return;

    try {
      const templateContent = await buildContentFromTemplate(
        stixCoreObjectId,
        templateId,
        maxContentMarkings,
      );
      const blob = new Blob([templateContent], { type });
      const file = new File([blob], fileName, { type });

      commitUploadFile({
        variables: { file, id: stixCoreObjectId, fileMarkings, fromTemplate: true },
        onCompleted: (result) => {
          setSubmitting(false);
          resetForm();
          handleCloseCreateContentFromTemplate();
          if (result.stixCoreObjectEdit?.importPush) {
            onFileChange(result.stixCoreObjectEdit.importPush.id);
          }
        },
      });
    } catch (e) {
      MESSAGING$.notifyError(t_i18n('An error occurred while trying to build content from template.'));
    }
  };

  const filesList = [...files, ...exportFiles.map((n) => ({ ...n, perspective: 'export' }))]
    .sort((a, b) => b.name.localeCompare(a.name));

  return (
    <Drawer
      variant="permanent"
      anchor="right"
      elevation={1}
      sx={{
        zIndex: 1100,
        width: 350,
        '& .MuiDrawer-paper': {
          width: 350,
          padding: '10px 0 20px 0',
          paddingTop: `calc(16px + 64px + ${settingsMessagesBannerHeight ?? 0}px)`, // 16 for margin, 64 for top bar,
        },
      }}
    >
      {!isNilField(content) && (
        <ContentBloc title={t_i18n('Mappable content')}>
          <List>
            <ListItemButton
              dense={true}
              divider={true}
              selected={contentSelected}
              onClick={handleSelectContent}
            >
              <ListItemIcon>
                <FileOutline fontSize="small" />
              </ListItemIcon>
              <ListItemText
                primary={t_i18n('Description & Main content')}
                secondary={t_i18n('Description and content of the entity')}
              />
            </ListItemButton>
          </List>
        </ContentBloc>
      )}

      <ContentBloc
        title={t_i18n('Files')}
        actions={(<>
          <Security needs={[KNOWLEDGE_KNUPLOAD]}>
            <FileUploader
              entityId={stixCoreObjectId}
              onUploadSuccess={onFileChange}
              size="small"
              nameInCallback={true}
            />
          </Security>
          <IconButton
            onClick={handleOpenCreate}
            color="primary"
            size="small"
            aria-label={t_i18n('Add a file')}
          >
            <AddOutlined />
          </IconButton>
        </>)}
      >
        <StixCoreObjectContentFilesList
          files={filesList}
          stixCoreObjectName={stixCoreObjectName}
          currentFileId={currentFileId}
          handleSelectFile={handleSelectFile}
          onFileChange={onFileChange}
        />
      </ContentBloc>

      {isContentFromTemplateEnabled && hasOutcomesTemplate && (
        <ContentBloc
          title={<>{t_i18n('Content from template')} {!isEnterpriseEdition && <EEChip />}</>}
          actions={isEnterpriseEdition && (
            <Tooltip title={t_i18n('Create an outcome based on a template')}>
              <IconButton
                onClick={handleOpenCreateContentFromTemplate}
                color="primary"
                size="small"
                aria-label={t_i18n('Create an outcome based on a template')}
              >
                <AddOutlined/>
              </IconButton>
            </Tooltip>
          )}
        >
          {isEnterpriseEdition && (
            <StixCoreObjectContentFilesList
              files={contentsFromTemplate}
              stixCoreObjectName={stixCoreObjectName}
              currentFileId={currentFileId}
              handleSelectFile={handleSelectFile}
              onFileChange={onFileChange}
            />
          )}
        </ContentBloc>
      )}

      <CreateFileForm
        isOpen={displayCreate}
        onClose={handleCloseCreate}
        onReset={handleCloseCreate}
        onSubmit={onSubmit}
      />

      {isEnterpriseEdition && isContentFromTemplateEnabled && hasOutcomesTemplate && (
        <ContentTemplateForm
          isOpen={displayCreateContentFromTemplate}
          onClose={handleCloseCreateContentFromTemplate}
          onReset={handleCloseCreateContentFromTemplate}
          onSubmit={onSubmitContentFromTemplate}
          templates={templates}
        />
      )}
    </Drawer>
  );
};

export default StixCoreObjectContentFiles;
