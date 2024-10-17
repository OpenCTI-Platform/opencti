import React, { FunctionComponent, useState } from 'react';
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
import makeStyles from '@mui/styles/makeStyles';
import EEChip from '@components/common/entreprise_edition/EEChip';
import { StixCoreObjectContent_stixCoreObject$data } from '@components/common/stix_core_objects/__generated__/StixCoreObjectContent_stixCoreObject.graphql';
import { FormikConfig } from 'formik/dist/types';
import ContentTemplateForm, { ContentTemplateFormInputs } from '@components/common/form/ContentTemplateForm';
import {
  StixCoreObjectContentFilesUploadStixCoreObjectMutation,
} from '@components/common/stix_core_objects/__generated__/StixCoreObjectContentFilesUploadStixCoreObjectMutation.graphql';
import CreateFileForm, { CreateFileFormInputs } from '@components/common/form/CreateFileForm';
import StixCoreObjectContentFilesList from '@components/common/stix_core_objects/StixCoreObjectContentFilesList';
import { useFormatter } from '../../../../components/i18n';
import FileUploader from '../files/FileUploader';
import { resolvedAttributesWidgets, templateAttribute, templateGraph, templateList, templateText, usedTemplateWidgets } from '../../../../utils/outcome_template/__template';
import useContentFromTemplate from '../../../../utils/outcome_template/engine/useContentFromTemplate';
import useEnterpriseEdition from '../../../../utils/hooks/useEnterpriseEdition';
import type { Template } from '../../../../utils/outcome_template/template';
import type { Theme } from '../../../../components/Theme';
import { isEmptyField } from '../../../../utils/utils';
import useHelper from '../../../../utils/hooks/useHelper';
import useApiMutation from '../../../../utils/hooks/useApiMutation';
import { MESSAGING$ } from '../../../../relay/environment';

// Deprecated - https://mui.com/system/styles/basics/
// Do not use it for new code.
const useStyles = makeStyles<Theme>((theme) => ({
  drawerPaper: {
    minHeight: '100vh',
    width: 350,
    padding: '10px 0 20px 0',
    position: 'fixed',
    zIndex: 1100,
  },
  toolbar: theme.mixins.toolbar,
}));

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
  content: string | null,
  handleSelectFile: (fileId: string) => void,
  handleSelectContent: () => void,
  contentSelected: boolean,
  currentFileId: string,
  onFileChange: (fileName?: string, isDeleted?: boolean) => void,
  settingsMessagesBannerHeight?: number,
  exportFiles: NonNullable<StixCoreObjectContent_stixCoreObject$data['exportFiles']>['edges'][number]['node'][],
  contentsFromTemplate: NonNullable<StixCoreObjectContent_stixCoreObject$data['contentsFromTemplate']>['edges'][number]['node'][],
}

const StixCoreObjectContentFiles: FunctionComponent<StixCoreObjectContentFilesProps> = ({
  files,
  stixCoreObjectId,
  content,
  handleSelectFile,
  handleSelectContent,
  contentSelected,
  currentFileId,
  onFileChange,
  settingsMessagesBannerHeight,
  exportFiles,
  contentsFromTemplate,
}) => {
  const classes = useStyles();
  const { t_i18n } = useFormatter();
  const { buildContentFromTemplate } = useContentFromTemplate();
  const isEnterpriseEdition = useEnterpriseEdition();
  const { isFeatureEnable } = useHelper();
  const isContentFromTemplateEnabled = isFeatureEnable('CONTENT_FROM_TEMPLATE');

  const [commitUploadFile] = useApiMutation<StixCoreObjectContentFilesUploadStixCoreObjectMutation>(
    stixCoreObjectContentFilesUploadStixCoreObjectMutation,
  );

  const [displayCreate, setDisplayCreate] = useState(false);
  const [displayCreateContentFromTemplate, setDisplayCreateContentFromTemplate] = useState(false);

  const hardcodedTemplates: Template[] = [templateGraph, templateList, templateAttribute, templateText];
  const hardcodedUsedTemplateWidgets = usedTemplateWidgets;
  const hardcodedResolvedAttributesWidgets = resolvedAttributesWidgets;

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
    const template = hardcodedTemplates.find((t) => t.name === values.template);

    if (!template) {
      MESSAGING$.notifyError(t_i18n('No template found for this name'));
      return;
    }

    const templateContent = await buildContentFromTemplate(
      stixCoreObjectId,
      template,
      hardcodedUsedTemplateWidgets,
      hardcodedResolvedAttributesWidgets,
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
  };

  const filesList = [...files, ...exportFiles.map((n) => ({ ...n, perspective: 'export' }))]
    .sort((a, b) => b.name.localeCompare(a.name));

  return (
    <Drawer
      variant="permanent"
      anchor="right"
      elevation={1}
      sx={{ zIndex: 1202 }}
      classes={{ paper: classes.drawerPaper }}
    >
      <div className={classes.toolbar} />
      {!isEmptyField(content) && (
        <>
          <Typography variant="body2" style={{ margin: '5px 0 0 15px' }}>{t_i18n('Mappable content')}</Typography>
          <List style={{ marginBottom: 30, marginTop: settingsMessagesBannerHeight }}>
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
                sx={{
                  '.MuiListItemText-secondary': {
                    whiteSpace: 'pre-line',
                  },
                }}
                primary={t_i18n('Description & Main content')}
                secondary={<div>
                  {t_i18n('Description and content of the entity')}
                </div>}
              />
            </ListItemButton>
          </List>
        </>
      )}

      <div>
        <Typography variant="body2" style={{ margin: '5px 0 0 15px', float: 'left' }}>
          {t_i18n('Files')}
        </Typography>
        <div style={{ float: 'right', display: 'flex', margin: '-4px 15px 0 0' }}>
          <FileUploader
            entityId={stixCoreObjectId}
            onUploadSuccess={onFileChange}
            size="small"
            nameInCallback={true}
          />
          <IconButton
            onClick={handleOpenCreate}
            color="primary"
            size="small"
            aria-label={t_i18n('Add a file')}
          >
            <AddOutlined />
          </IconButton>
        </div>
      </div>

      <StixCoreObjectContentFilesList
        files={filesList}
        currentFileId={currentFileId}
        handleSelectFile={handleSelectFile}
        onFileChange={onFileChange}
      />

      {isContentFromTemplateEnabled && (
        <div>
          <Typography variant="body2" style={{ margin: '5px 0 0 15px', float: 'left' }}>
            {t_i18n('Content from template')}
          </Typography>
          {!isEnterpriseEdition ? <EEChip/> : (
            <div style={{ float: 'right', display: 'flex', margin: '-4px 15px 0 0' }}>
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
            </div>
          )}
        </div>
      )}

      {isEnterpriseEdition && isContentFromTemplateEnabled && (
        <StixCoreObjectContentFilesList
          files={contentsFromTemplate}
          currentFileId={currentFileId}
          handleSelectFile={handleSelectFile}
          onFileChange={onFileChange}
        />
      )}

      <CreateFileForm
        isOpen={displayCreate}
        onClose={handleCloseCreate}
        onReset={handleCloseCreate}
        onSubmit={onSubmit}
      />

      {isEnterpriseEdition && isContentFromTemplateEnabled && (
        <ContentTemplateForm
          isOpen={displayCreateContentFromTemplate}
          onClose={handleCloseCreateContentFromTemplate}
          onReset={handleCloseCreateContentFromTemplate}
          onSubmit={onSubmitContentFromTemplate}
          templates={hardcodedTemplates.map((t) => t.name)}
        />
      )}
    </Drawer>
  );
};

export default StixCoreObjectContentFiles;
