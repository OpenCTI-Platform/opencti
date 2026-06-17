import Button from '@common/button/Button';
import Dialog from '@common/dialog/Dialog';
import DialogActions from '@mui/material/DialogActions';
import TextField from '@mui/material/TextField';
import { Form, Formik } from 'formik';
import { graphql } from 'react-relay';
import { useFormatter } from 'src/components/i18n';
import { type SavedFiltersSelectionData } from 'src/components/saved_filters/SavedFilterSelection';
import useApiMutation from '../../utils/hooks/useApiMutation';
import useAuth from '../../utils/hooks/useAuth';
import useGranted, { KNOWLEDGE_KNSHAREFILTERS } from '../../utils/hooks/useGranted';
import { AccessRight, type AuthorizedMemberOption } from '../../utils/authorizedMembers';
import { type AuthorizedMembersFieldValue } from '@components/common/form/AuthorizedMembersField';
import SavedFilterSharingSection from './SavedFilterSharingSection';
import Security from '../../utils/Security';
import useHelper from '../../utils/hooks/useHelper';

const savedFilterFieldPatchMutation = graphql`
  mutation SavedFilterEditDialogFieldPatchMutation($id: ID!, $input: [EditInput!]!) {
    savedFilterFieldPatch(id: $id, input: $input) {
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

const savedFilterEditAuthorizedMembersMutation = graphql`
  mutation SavedFilterEditDialogAuthorizedMembersMutation($id: ID!, $input: [MemberAccessInput!]!) {
    savedFilterEditAuthorizedMembers(id: $id, input: $input) {
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

type SavedFilterEditDialogProps = {
  onClose: () => void;
  isOpen: boolean;
  savedFilter: SavedFiltersSelectionData;
  onSaved?: () => void;
};

interface SavedFilterEditFormValues {
  name: string;
  authorized_members: AuthorizedMembersFieldValue;
}

const SavedFilterEditDialog = ({
  isOpen,
  onClose,
  savedFilter,
  onSaved,
}: SavedFilterEditDialogProps) => {
  const { t_i18n } = useFormatter();
  const { me } = useAuth();
  const hasShareFilterCapability = useGranted([KNOWLEDGE_KNSHAREFILTERS]);

  const { isFeatureEnable } = useHelper();
  const isSharingSavedFiltersFeatureEnabled = isFeatureEnable('SHARE_FILTERS');

  const owner = { id: me.id, name: me.name, entity_type: 'User' };

  const [commitFieldPatch] = useApiMutation(
    savedFilterFieldPatchMutation,
    undefined,
    { successMessage: t_i18n('Saved filter successfully updated') },
  );

  const [commitAuthorizedMembers] = useApiMutation(
    savedFilterEditAuthorizedMembersMutation,
  );

  const handleSubmit = (values: SavedFilterEditFormValues) => {
    // Update name
    if (values.name !== savedFilter.name) {
      commitFieldPatch({
        variables: {
          id: savedFilter.id,
          input: [{ key: 'name', value: [values.name] }],
        },
        onCompleted: () => onSaved?.(),
      });
    }

    // Update authorized members
    if (isSharingSavedFiltersFeatureEnabled && hasShareFilterCapability && values.authorized_members) {
      const memberAccessInput = values.authorized_members.map((m: AuthorizedMemberOption) => ({
        id: m.value,
        access_right: m.accessRight,
      }));
      commitAuthorizedMembers({
        variables: {
          id: savedFilter.id,
          input: memberAccessInput,
        },
        onCompleted: () => onSaved?.(),
      });
    }

    onClose();
  };

  const initialAuthorizedMembers: AuthorizedMembersFieldValue = savedFilter.authorizedMembers
    ? savedFilter.authorizedMembers.map((m) => ({
        value: m.member_id ?? m.id,
        label: m.name ?? '',
        type: m.entity_type,
        accessRight: (m.access_right ?? 'view') as AccessRight,
        groupsRestriction: [] as { value: string; label: string }[],
      }))
    : null;

  const initialValues = {
    name: savedFilter.name,
    authorized_members: initialAuthorizedMembers,
  };

  return (
    <Dialog
      open={isOpen}
      onClose={onClose}
      size="medium"
      title={t_i18n('Edit saved filter')}
    >
      <Formik<SavedFilterEditFormValues>
        initialValues={initialValues}
        enableReinitialize
        onSubmit={handleSubmit}
      >
        {({ submitForm, values, setFieldValue }) => (
          <Form>
            <TextField
              label={t_i18n('Name')}
              placeholder={t_i18n('My saved filter')}
              fullWidth
              value={values.name}
              onChange={(e) => setFieldValue('name', e.target.value)}
            />
            {isSharingSavedFiltersFeatureEnabled
              && (
                <Security needs={[KNOWLEDGE_KNSHAREFILTERS]}>
                  <SavedFilterSharingSection
                    owner={owner}
                    isEditMode
                  />
                </Security>
              )
            }
            <DialogActions>
              <Button variant="secondary" onClick={onClose}>{t_i18n('Cancel')}</Button>
              <Button onClick={submitForm} disabled={!values.name}>{t_i18n('Save')}</Button>
            </DialogActions>
          </Form>
        )}
      </Formik>
    </Dialog>
  );
};

export default SavedFilterEditDialog;
