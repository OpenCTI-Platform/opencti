import Button from '@common/button/Button';
import Dialog from '@common/dialog/Dialog';
import Autocomplete from '@mui/material/Autocomplete';
import Chip from '@mui/material/Chip';
import DialogActions from '@mui/material/DialogActions';
import MuiTextField from '@mui/material/TextField';
import { FunctionComponent, useState } from 'react';
import { graphql, PreloadedQuery, usePreloadedQuery } from 'react-relay';
import { useFormatter } from '../../../../../components/i18n';
import useApiMutation from '../../../../../utils/hooks/useApiMutation';
import { EntitySettingCustomFieldsAddDialogAddMutation } from './__generated__/EntitySettingCustomFieldsAddDialogAddMutation.graphql';
import { EntitySettingCustomFieldsQuery } from './__generated__/EntitySettingCustomFieldsQuery.graphql';
import { CustomFieldDefinitionNode, entitySettingCustomFieldsQuery, getCustomFieldTypeLabel } from './EntitySettingCustomFields';

const entitySettingCustomFieldsAddDialogAddMutation = graphql`
  mutation EntitySettingCustomFieldsAddDialogAddMutation($id: ID!, $entityType: String!) {
    customFieldDefinitionAddEntityType(id: $id, entityType: $entityType) {
      id
      entity_types
    }
  }
`;

interface EntitySettingCustomFieldsAddDialogProps {
  queryRef: PreloadedQuery<EntitySettingCustomFieldsQuery>;
  open: boolean;
  onClose: () => void;
  entityType: string;
  onAdded: () => void;
}

const EntitySettingCustomFieldsAddDialog: FunctionComponent<EntitySettingCustomFieldsAddDialogProps> = ({
  queryRef,
  open,
  onClose,
  entityType,
  onAdded,
}) => {
  const { t_i18n } = useFormatter();
  const data = usePreloadedQuery(entitySettingCustomFieldsQuery, queryRef);
  const allCustomFields: CustomFieldDefinitionNode[] = (data.customFieldDefinitions?.edges ?? []).map((edge) => edge.node);
  const candidates = allCustomFields.filter((cf) => !(cf.entity_types ?? []).includes(entityType));

  const [selected, setSelected] = useState<CustomFieldDefinitionNode[]>([]);
  const [submitting, setSubmitting] = useState(false);
  const [commitAdd] = useApiMutation<EntitySettingCustomFieldsAddDialogAddMutation>(entitySettingCustomFieldsAddDialogAddMutation);

  const handleClose = () => {
    setSelected([]);
    onClose();
  };

  const handleSubmit = () => {
    setSubmitting(true);
    Promise.all(selected.map((cf) => new Promise<void>((resolve, reject) => {
      commitAdd({
        variables: { id: cf.id, entityType },
        onCompleted: () => resolve(),
        onError: (error: Error) => reject(error),
      });
    }))).then(() => {
      setSubmitting(false);
      setSelected([]);
      onAdded();
      onClose();
    }).catch(() => {
      setSubmitting(false);
    });
  };

  return (
    <Dialog open={open} onClose={handleClose} title={t_i18n('Add a custom field')}>
      <Autocomplete
        multiple
        options={candidates}
        value={selected}
        noOptionsText={t_i18n('No available custom field')}
        getOptionLabel={(cf) => `${cf.label} (${getCustomFieldTypeLabel(cf.field_type, t_i18n)})`}
        isOptionEqualToValue={(option, value) => option.id === value.id}
        onChange={(_, newValue) => setSelected(newValue)}
        renderTags={(tagValue, getTagProps) => tagValue.map((option, index) => {
          const { key, ...tagProps } = getTagProps({ index });
          return (
            <Chip key={key} label={option.label} {...tagProps} />
          );
        })}
        renderInput={(params) => (
          <MuiTextField
            {...params}
            variant="standard"
            label={t_i18n('Custom fields')}
          />
        )}
      />
      <DialogActions>
        <Button variant="secondary" onClick={handleClose} disabled={submitting}>
          {t_i18n('Cancel')}
        </Button>
        <Button onClick={handleSubmit} disabled={submitting || selected.length === 0}>
          {t_i18n('Add')}
        </Button>
      </DialogActions>
    </Dialog>
  );
};

export default EntitySettingCustomFieldsAddDialog;
