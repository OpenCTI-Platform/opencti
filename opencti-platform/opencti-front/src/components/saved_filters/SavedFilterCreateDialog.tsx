import Button from '@common/button/Button';
import Dialog from '@common/dialog/Dialog';
import DialogActions from '@mui/material/DialogActions';
import TextField from '@mui/material/TextField';
import { ChangeEvent, useState } from 'react';
import { Form, Formik } from 'formik';
import { graphql } from 'react-relay';
import { useDataTableContext } from 'src/components/dataGrid/components/DataTableContext';
import { useFormatter } from 'src/components/i18n';
import { type SavedFiltersSelectionData } from 'src/components/saved_filters/SavedFilterSelection';
import { SavedFilterCreateDialogMutation$data } from 'src/components/saved_filters/__generated__/SavedFilterCreateDialogMutation.graphql';
import { insertNode } from 'src/utils/store';
import useApiMutation from '../../utils/hooks/useApiMutation';
import useAuth from '../../utils/hooks/useAuth';
import { KNOWLEDGE_KNSHAREFILTERS } from '../../utils/hooks/useGranted';
import useHelper from '../../utils/hooks/useHelper';
import { type AuthorizedMemberOption } from '../../utils/authorizedMembers';
import { type AuthorizedMembersFieldValue } from '@components/common/form/AuthorizedMembersField';
import getSavedFilterScopeFilter from './getSavedFilterScopeFilter';
import SavedFilterSharingSection from './SavedFilterSharingSection';
import Security from '../../utils/Security';

const savedFilterCreateDialogMutation = graphql`
  mutation SavedFilterCreateDialogMutation($input: SavedFilterAddInput!) {
    savedFilterAdd(input: $input) {
      id
      name
      filters
      scope
      creator_id
      currentUserAccessRight
      authorizedMembers {
        id
        name
        entity_type
        access_right
        member_id
      }
    }
  }
`;

type SavedFilterDialogProps = {
  onClose: () => void;
  isOpen: boolean;
  setCurrentSavedFilter: (savedFilter: SavedFiltersSelectionData | undefined) => void;
};

interface SavedFilterFormValues {
  authorized_members: AuthorizedMembersFieldValue;
}

const SavedFilterCreateDialog = ({ isOpen, onClose, setCurrentSavedFilter }: SavedFilterDialogProps) => {
  const { t_i18n } = useFormatter();
  const { me } = useAuth();

  const { isFeatureEnable } = useHelper();
  const isSharingSavedFiltersFeatureEnabled = isFeatureEnable('SHARE_FILTERS');

  const owner = { id: me.id, name: me.name, entity_type: 'User' };

  const {
    useDataTablePaginationLocalStorage: {
      localStorageKey,
      helpers,
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

  const handleSubmitSaveFilter = (values: SavedFilterFormValues) => {
    const restrictedMembers = values.authorized_members
      ? values.authorized_members.map((m: AuthorizedMemberOption) => ({
          id: m.value,
          access_right: m.accessRight,
        }))
      : undefined;

    commit({
      variables: {
        input: {
          name: filterName,
          filters: JSON.stringify(filters),
          scope: localStorageKey,
          authorized_members: restrictedMembers,
        },
      },
      updater: (store) => {
        const scopeFilter = getSavedFilterScopeFilter(localStorageKey);
        insertNode(store, 'SavedFilters_savedFilters', { filters: scopeFilter }, 'savedFilterAdd');
      },
      onCompleted: (response) => {
        const { savedFilterAdd } = response as SavedFilterCreateDialogMutation$data;
        if (!savedFilterAdd) return;
        setCurrentSavedFilter(savedFilterAdd);
        helpers.handleChangeSavedFilters(savedFilterAdd);
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
      onClose={onClose}
      size="medium"
      title={t_i18n('Save filter')}
    >
      <Formik<SavedFilterFormValues>
        initialValues={{ authorized_members: null }}
        onSubmit={handleSubmitSaveFilter}
      >
        {({ submitForm }) => (
          <Form>
            <TextField
              label={t_i18n('Name')}
              placeholder={t_i18n('My saved filter')}
              fullWidth
              value={filterName}
              onChange={handleChange}
            />
            {isSharingSavedFiltersFeatureEnabled
              && (
                <Security needs={[KNOWLEDGE_KNSHAREFILTERS]}>
                  <SavedFilterSharingSection
                    owner={owner}
                  />
                </Security>
              )
            }
            <DialogActions>
              <Button variant="secondary" onClick={onClose}>{t_i18n('Cancel')}</Button>
              <Button onClick={submitForm} disabled={!filterName}>{t_i18n('Save')}</Button>
            </DialogActions>
          </Form>
        )}
      </Formik>
    </Dialog>
  );
};

export default SavedFilterCreateDialog;
