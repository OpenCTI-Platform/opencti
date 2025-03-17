import React, { useState } from 'react';
import IconButton from '@mui/material/IconButton';
import { SaveOutlined } from '@mui/icons-material';
import { useFormatter } from 'src/components/i18n';
import SavedFilterDialog from './SavedFilterDialog';

const SavedFilterButton = () => {
  const { t_i18n } = useFormatter();

  const [isSavedDialogOpen, setIsSavedDialogOpen] = useState<boolean>(false);

  const handleOpenDialog = () => setIsSavedDialogOpen(true);
  const handleCloseDialog = () => setIsSavedDialogOpen(false);

  return (
    <>
      <IconButton
        color="primary"
        onClick={handleOpenDialog}
        size="medium"
        aria-label={t_i18n('Save')}
      >
        <SaveOutlined />
      </IconButton>

      {isSavedDialogOpen && (
        <SavedFilterDialog
          isOpen={isSavedDialogOpen}
          onClose={handleCloseDialog}
        />
      )}
    </>
  );
};

export default SavedFilterButton;
