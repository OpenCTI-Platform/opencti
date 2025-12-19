import React, { FunctionComponent, ReactNode, useState } from 'react';
import List from '@mui/material/List';
import ListItem from '@mui/material/ListItem';
import ListItemText from '@mui/material/ListItemText';
import Drawer from '@mui/material/Drawer';
import ListItemIcon from '@mui/material/ListItemIcon';
import { FileExportOutline, FileOutline, InformationOutline } from 'mdi-material-ui';
import IconButton from '@common/button/IconButton';
import Tooltip from '@mui/material/Tooltip';
import { AddOutlined, MoreVert } from '@mui/icons-material';
import { graphql } from 'react-relay';
import ListItemButton from '@mui/material/ListItemButton';
import Typography from '@mui/material/Typography';
import EEChip from '@components/common/entreprise_edition/EEChip';
import { StixCoreObjectContent_stixCoreObject$data } from '@components/common/stix_core_objects/__generated__/StixCoreObjectContent_stixCoreObject.graphql';
import { FormikConfig } from 'formik/dist/types';
import {
  StixCoreObjectContentFilesUploadStixCoreObjectMutation,
} from '@components/common/stix_core_objects/__generated__/StixCoreObjectContentFilesUploadStixCoreObjectMutation.graphql';
import CreateFileForm, { CreateFileFormInputs } from '@components/common/form/CreateFileForm';
import StixCoreObjectContentFilesList from '@components/common/stix_core_objects/StixCoreObjectContentFilesList';
import { useSettingsMessagesBannerHeight } from '@components/settings/settings_messages/SettingsMessagesBanner';
import StixCoreObjectFileExport, { BUILT_IN_FROM_TEMPLATE, BUILT_IN_HTML_TO_PDF } from '@components/common/stix_core_objects/StixCoreObjectFileExport';
import MenuItem from '@mui/material/MenuItem';
import Menu from '@mui/material/Menu';
import { useFormatter } from '../../../../components/i18n';
import FileUploader from '../files/FileUploader';
import useEnterpriseEdition from '../../../../utils/hooks/useEnterpriseEdition';
import { isNilField } from '../../../../utils/utils';
import useApiMutation from '../../../../utils/hooks/useApiMutation';
import { KNOWLEDGE_KNGETEXPORT, KNOWLEDGE_KNUPLOAD } from '../../../../utils/hooks/useGranted';
import Security from '../../../../utils/Security';
import useDraftContext from '../../../../utils/hooks/useDraftContext';

interface ContentBlocProps {
  title: ReactNode;
  children: ReactNode;
  actions?: ReactNode;
}

const ContentBloc = ({ title, actions, children }: ContentBlocProps) => {
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
  files: NonNullable<StixCoreObjectContent_stixCoreObject$data['importFiles']>['edges'][number]['node'][];
  stixCoreObjectId: string;
  stixCoreObjectName: string;
  stixCoreObjectType: string;
  content: string | null;
  handleSelectFile: (fileId: string) => void;
  handleSelectContent: () => void;
  contentSelected: boolean;
  currentFileId: string;
  onFileChange: (fileName?: string, isDeleted?: boolean) => void;
  exportFiles: NonNullable<StixCoreObjectContent_stixCoreObject$data['exportFiles']>['edges'][number]['node'][];
  filesFromTemplate: NonNullable<StixCoreObjectContent_stixCoreObject$data['filesFromTemplate']>['edges'][number]['node'][];
  hasOutcomesTemplate?: boolean;
}

const StixCoreObjectContentFiles: FunctionComponent<StixCoreObjectContentFilesProps> = ({
  files,
  stixCoreObjectId,
  stixCoreObjectName,
  stixCoreObjectType,
  content,
  handleSelectFile,
  handleSelectContent,
  contentSelected,
  currentFileId,
  onFileChange,
  exportFiles,
  filesFromTemplate,
  hasOutcomesTemplate,
}) => {
  const { t_i18n } = useFormatter();
  const draftContext = useDraftContext();
  const isEnterpriseEdition = useEnterpriseEdition();
  const settingsMessagesBannerHeight = useSettingsMessagesBannerHeight();

  const [anchorEl, setAnchorEl] = useState<HTMLElement | null>(null);
  const [displayCreate, setDisplayCreate] = useState(false);

  const [commitUploadFile] = useApiMutation<StixCoreObjectContentFilesUploadStixCoreObjectMutation>(
    stixCoreObjectContentFilesUploadStixCoreObjectMutation,
  );

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
        setDisplayCreate(false);
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
            <ListItem
              dense={true}
              divider={true}
              disablePadding
              secondaryAction={!draftContext && (
                <Security needs={[KNOWLEDGE_KNUPLOAD, KNOWLEDGE_KNGETEXPORT]} matchAll>
                  <IconButton
                    onClick={(e) => {
                      e.stopPropagation();
                      setAnchorEl(e.currentTarget);
                    }}
                    aria-haspopup="true"
                    color="primary"
                    size="small"
                  >
                    <MoreVert />
                  </IconButton>
                </Security>
              )
              }
            >
              <ListItemButton
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
            </ListItem>
          </List>
          <Menu
            anchorEl={anchorEl}
            open={Boolean(anchorEl)}
            onClose={() => setAnchorEl(null)}
          >
            <StixCoreObjectFileExport
              onClose={() => setAnchorEl(null)}
              scoId={stixCoreObjectId}
              scoName={stixCoreObjectName}
              scoEntityType={stixCoreObjectType}
              defaultValues={{
                connector: BUILT_IN_HTML_TO_PDF.value,
                format: 'application/pdf',
                fileToExport: 'mappableContent',
              }}
              onExportCompleted={onFileChange}
              OpenFormComponent={({ onOpen }) => (
                <MenuItem onClick={onOpen}>
                  {t_i18n('Generate a PDF export')}
                </MenuItem>
              )}
            />
          </Menu>
        </ContentBloc>
      )}

      <ContentBloc
        title={t_i18n('Files')}
        actions={(
          <Security needs={[KNOWLEDGE_KNUPLOAD]}>
            <>
              <FileUploader
                entityId={stixCoreObjectId}
                onUploadSuccess={onFileChange}
                nameInCallback={true}
              />
              <IconButton
                onClick={() => setDisplayCreate(true)}
                color="primary"
                size="small"
                aria-label={t_i18n('Add a file')}
              >
                <AddOutlined />
              </IconButton>
            </>
          </Security>
        )}
      >
        <StixCoreObjectContentFilesList
          files={filesList}
          stixCoreObjectId={stixCoreObjectId}
          stixCoreObjectName={stixCoreObjectName}
          stixCoreObjectType={stixCoreObjectType}
          currentFileId={currentFileId}
          handleSelectFile={handleSelectFile}
          onFileChange={onFileChange}
        />
      </ContentBloc>

      {hasOutcomesTemplate && (
        <ContentBloc
          title={(
            <>
              {t_i18n('Generated finished intelligence')} {!isEnterpriseEdition && <EEChip />}
              {isEnterpriseEdition
                && (
                  <Tooltip
                    title={t_i18n('Files generated from a template')}
                  >
                    <InformationOutline
                      fontSize="small"
                      color="primary"
                      style={{ marginLeft: 5 }}
                    />
                  </Tooltip>
                )}
            </>
          )}
          actions={!draftContext && isEnterpriseEdition && (
            <StixCoreObjectFileExport
              scoId={stixCoreObjectId}
              scoName={stixCoreObjectName}
              scoEntityType={stixCoreObjectType}
              defaultValues={{
                connector: BUILT_IN_FROM_TEMPLATE.value,
                format: 'text/html',
              }}
              onExportCompleted={onFileChange}
              OpenFormComponent={({ onOpen }) => (
                <Security needs={[KNOWLEDGE_KNUPLOAD, KNOWLEDGE_KNGETEXPORT]} matchAll>
                  <Tooltip title={t_i18n('Generate an export based on a template')}>
                    <IconButton
                      onClick={onOpen}
                      color="primary"
                      size="small"
                      aria-label={t_i18n('Generate an export based on a template')}
                    >
                      <FileExportOutline />
                    </IconButton>
                  </Tooltip>
                </Security>
              )}
            />
          )}
        >
          {isEnterpriseEdition && (
            <StixCoreObjectContentFilesList
              files={filesFromTemplate}
              stixCoreObjectId={stixCoreObjectId}
              stixCoreObjectName={stixCoreObjectName}
              stixCoreObjectType={stixCoreObjectType}
              currentFileId={currentFileId}
              handleSelectFile={handleSelectFile}
              onFileChange={onFileChange}
            />
          )}
        </ContentBloc>
      )}

      <CreateFileForm
        isOpen={displayCreate}
        onClose={() => setDisplayCreate(false)}
        onReset={() => setDisplayCreate(false)}
        onSubmit={onSubmit}
      />
    </Drawer>
  );
};

export default StixCoreObjectContentFiles;
