import React, { useState, ChangeEvent } from 'react';
import DialogTitle from '@mui/material/DialogTitle';
import DialogContent from '@mui/material/DialogContent';
import DialogActions from '@mui/material/DialogActions';
import Button from '@mui/material/Button';
import Dialog from '@mui/material/Dialog';
import { useFormatter } from 'src/components/i18n';
import TextField from '@mui/material/TextField';
import { graphql } from 'react-relay';
import { useDataTableContext } from 'src/components/dataGrid/components/DataTableContext';
import { insertNode } from 'src/utils/store';
import useApiMutation from '../../utils/hooks/useApiMutation';
import getSavedFilterScopeFilter from './getSavedFilterScopeFilter';

const savedFilterCreateDialogMutation = graphql`
  mutation SavedFilterCreateDialogMutation($input: SavedFilterAddInput!) {
    savedFilterAdd(input: $input) {
      id
      name
      filters
      scope
    }
  }
`;

type SavedFilterDialogProps = {
  onClose: () => void;
  isOpen: boolean;
};

const SavedFilterCreateDialog = ({ isOpen, onClose }: SavedFilterDialogProps) => {
  const { t_i18n } = useFormatter();

  const {
    useDataTablePaginationLocalStorage: {
      localStorageKey,
      viewStorage: { filters },
    },
  } = useDataTableContext();

  const [filterName, setFilterName] = useState<string>();

  const [commit] = useApiMutation(
    savedFilterCreateDialogMutation,
    undefined,
    {
      successMessage: t_i18n('Saved filter successfully created'),
    },
  );

  const handleChange = (event: ChangeEvent<HTMLInputElement>) => {
    if (event.target.value === '') setFilterName(undefined);
    else setFilterName(event.target.value);
  };
  const handleSubmitSaveFilter = () => {
    commit({
      variables: {
        input: {
          name: filterName,
          filters: JSON.stringify(filters),
          scope: localStorageKey,
        },
      },
      updater: (store) => {
        const scopeFilter = getSavedFilterScopeFilter(localStorageKey);
        insertNode(store, 'SavedFilters__savedFilters', { filters: scopeFilter }, 'savedFilterAdd');
      },
      onCompleted: () => {
        onClose();
      },
      onError: () => {
        onClose();
      },
    });
  };

  return (
    <Dialog
      open={isOpen}
      PaperProps={{ elevation: 1 }}
      onClose={onClose}
      fullWidth
      maxWidth="xs"
    >
      <DialogTitle>{t_i18n('Save Filter')}</DialogTitle>
      <DialogContent>
        <TextField
          label={t_i18n('Name')}
          placeholder={t_i18n('my saved filter')}
          fullWidth
          value={filterName}
          onChange={handleChange}
        />
      </DialogContent>
      <DialogActions>
        <Button onClick={onClose}>{t_i18n('Cancel')}</Button>
        <Button onClick={handleSubmitSaveFilter} disabled={!filterName} color="secondary">{t_i18n('Save')}</Button>
      </DialogActions>
    </Dialog>
  );
};

export default SavedFilterCreateDialog;
