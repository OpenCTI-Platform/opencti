import { Button, IconButton, Tooltip, TooltipContent, TooltipTrigger } from '@filigran/design-system';
import ImportFilesDialog from '@components/common/files/import_files/ImportFilesDialog';
import { FileUploadOutlined } from '@mui/icons-material';
import React, { useState } from 'react';
import { useGetCurrentUserAccessRight } from '../utils/authorizedMembers';
import useDraftContext from '../utils/hooks/useDraftContext';
import { useFormatter } from './i18n';

interface UploadImportProps {
  size?: 'small' | 'default';
  fontSize?: 'small' | 'medium' | 'large';
  variant?: 'text' | 'contained' | 'outlined' | 'icon';
  style?: React.CSSProperties;
  onSuccess?: () => void;
  entityId?: string;
}

const UploadImport = ({
  size = 'default',
  variant = 'icon',
  fontSize = 'medium',
  onSuccess,
  entityId,
}: UploadImportProps) => {
  const { t_i18n } = useFormatter();
  const title = t_i18n('Import data');
  const librarySize = size === 'small' ? 'sm' : 'md';
  const [openImportFilesDialog, setOpenImportFilesDialog] = useState(false);
  // Remove import button in Draft context without the minimal right access "canEdit"
  const draftContext = useDraftContext();
  const currentAccessRight = useGetCurrentUserAccessRight(draftContext?.currentUserAccessRight);
  const canDisplayButton = !draftContext || currentAccessRight.canEdit;

  return canDisplayButton && (
    <>
      {openImportFilesDialog && (
        <ImportFilesDialog
          open={openImportFilesDialog}
          handleClose={() => {
            onSuccess?.();
            setOpenImportFilesDialog(false);
          }}
          entityId={entityId}
        />
      )}
      {variant === 'icon' ? (
        <Tooltip>
          <TooltipTrigger asChild>
            <IconButton
              size={librarySize}
              priority="tertiary"
              aria-haspopup="true"
              aria-label={title}
              onClick={() => setOpenImportFilesDialog(true)}
              icon={<FileUploadOutlined fontSize={fontSize} />}
            />
          </TooltipTrigger>
          <TooltipContent>{title}</TooltipContent>
        </Tooltip>
      ) : (
        // Importing data is not an AI affordance: this keeps the default
        // variant, where the product's own button was `primary`.
        <Button
          size={librarySize}
          onClick={() => setOpenImportFilesDialog(true)}
          aria-label={title}
          title={title}
        >
          {title}
        </Button>
      )}
    </>
  );
};

export default UploadImport;
