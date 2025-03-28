import React, { useState } from 'react';
import IconButton from '@mui/material/IconButton';
import { SaveOutlined } from '@mui/icons-material';
import { useFormatter } from 'src/components/i18n';
import Tooltip from '@mui/material/Tooltip';
import SavedFilterCreateDialog from 'src/components/saved_filters/SavedFilterCreateDialog';
import { useDataTableContext } from 'src/components/dataGrid/components/DataTableContext';

const SavedFilterButton = () => {
  const { t_i18n } = useFormatter();

  const [isSavedDialogOpen, setIsSavedDialogOpen] = useState<boolean>(false);

  const {
    useDataTablePaginationLocalStorage: {
      viewStorage: { filters },
    },
  } = useDataTableContext();

  const handleOpenDialog = () => setIsSavedDialogOpen(true);
  const handleCloseDialog = () => setIsSavedDialogOpen(false);

  return (
    <>
      <Tooltip title={t_i18n('Save filter')}>
        <IconButton
          color="primary"
          onClick={handleOpenDialog}
          size="small"
          disabled={!filters?.filters.length && !filters?.filterGroups.length}
          aria-label={t_i18n('Save')}
        >
          <SaveOutlined />
        </IconButton>
      </Tooltip>

      {isSavedDialogOpen && (
        <SavedFilterCreateDialog
          isOpen={isSavedDialogOpen}
          onClose={handleCloseDialog}
        />
      )}
    </>
  );
};

export default SavedFilterButton;
