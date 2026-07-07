import Card from '@common/card/Card';
import Button from '@common/button/Button';
import IconButton from '@common/button/IconButton';
import Dialog from '@common/dialog/Dialog';
import DeleteOutlined from '@mui/icons-material/DeleteOutlined';
import EditOutlined from '@mui/icons-material/EditOutlined';
import DialogActions from '@mui/material/DialogActions';
import FormControlLabel from '@mui/material/FormControlLabel';
import MenuItem from '@mui/material/MenuItem';
import Switch from '@mui/material/Switch';
import MuiTextField from '@mui/material/TextField';
import Table from '@mui/material/Table';
import TableBody from '@mui/material/TableBody';
import TableCell from '@mui/material/TableCell';
import TableHead from '@mui/material/TableHead';
import TableRow from '@mui/material/TableRow';
import { FunctionComponent, Suspense, useState } from 'react';
import { graphql, PreloadedQuery, usePreloadedQuery } from 'react-relay';
import Loader, { LoaderVariant } from '../../../../../components/Loader';
import { useFormatter } from '../../../../../components/i18n';
import MarkdownFieldBase from '../../../../../components/fields/markdownField/MarkdownFieldBase';
import useApiMutation from '../../../../../utils/hooks/useApiMutation';
import { useQueryLoadingWithLoadQuery } from '../../../../../utils/hooks/useQueryLoading';
import { useSubTypeOutletContext } from '../SubTypeOutletContext';
import EntitySettingCustomFieldsAddDialog from './EntitySettingCustomFieldsAddDialog';
import { EntitySettingCustomFieldsQuery, EntitySettingCustomFieldsQuery$data } from './__generated__/EntitySettingCustomFieldsQuery.graphql';

export const entitySettingCustomFieldsQuery = graphql`
  query EntitySettingCustomFieldsQuery {
    customFieldDefinitions(first: 500, orderBy: label, orderMode: asc) {
      edges {
        node {
          id
          name
          label
          field_type
          select_options
          entity_types
          entity_type_settings {
            entity_type
            mandatory
            default_value
          }
        }
      }
    }
  }
`;

const entitySettingCustomFieldsRemoveMutation = graphql`
  mutation EntitySettingCustomFieldsRemoveMutation($id: ID!, $entityType: String!) {
    customFieldDefinitionRemoveEntityType(id: $id, entityType: $entityType) {
      id
      entity_types
    }
  }
`;

const entitySettingCustomFieldsUpdateMutation = graphql`
  mutation EntitySettingCustomFieldsUpdateMutation($id: ID!, $entityType: String!, $mandatory: Boolean!, $default_value: String) {
    customFieldDefinitionUpdateEntityType(id: $id, entityType: $entityType, mandatory: $mandatory, default_value: $default_value) {
      id
      entity_types
      entity_type_settings {
        entity_type
        mandatory
        default_value
      }
    }
  }
`;

export type CustomFieldDefinitionNode = NonNullable<NonNullable<EntitySettingCustomFieldsQuery$data['customFieldDefinitions']>['edges']>[number]['node'];

// Maps the internal field_type value to the same human-readable label used in the custom field creation form.
export const getCustomFieldTypeLabel = (fieldType: string, t_i18n: (s: string) => string) => {
  switch (fieldType) {
    case 'integer':
      return t_i18n('Number');
    case 'boolean':
      return t_i18n('Boolean');
    case 'date':
      return t_i18n('Date');
    case 'select':
      return t_i18n('Selection list');
    case 'multi_select':
      return t_i18n('Multiple selection list');
    case 'markdown':
      return t_i18n('Markdown');
    default:
      return t_i18n('Text');
  }
};

interface EntitySettingCustomFieldsTableProps {
  queryRef: PreloadedQuery<EntitySettingCustomFieldsQuery>;
  entityType: string;
  refresh: () => void;
}

const getEntityTypeSetting = (cf: CustomFieldDefinitionNode, entityType: string) => (cf.entity_type_settings ?? []).find((setting) => setting.entity_type === entityType);

interface EntitySettingCustomFieldEditDialogProps {
  customField: CustomFieldDefinitionNode;
  entityType: string;
  open: boolean;
  onClose: () => void;
  onUpdated: () => void;
}

const EntitySettingCustomFieldEditDialog: FunctionComponent<EntitySettingCustomFieldEditDialogProps> = ({
  customField,
  entityType,
  open,
  onClose,
  onUpdated,
}) => {
  const { t_i18n } = useFormatter();
  const currentSetting = getEntityTypeSetting(customField, entityType);
  const [mandatory, setMandatory] = useState(currentSetting?.mandatory ?? false);
  const [defaultValue, setDefaultValue] = useState(currentSetting?.default_value ?? '');
  const [submitting, setSubmitting] = useState(false);
  const [commitUpdate] = useApiMutation(entitySettingCustomFieldsUpdateMutation);

  const handleSubmit = () => {
    setSubmitting(true);
    commitUpdate({
      variables: {
        id: customField.id,
        entityType,
        mandatory,
        default_value: defaultValue === '' ? null : defaultValue,
      },
      onCompleted: () => {
        setSubmitting(false);
        onUpdated();
        onClose();
      },
      onError: () => {
        setSubmitting(false);
      },
    });
  };

  const renderDefaultValueField = () => {
    switch (customField.field_type) {
      case 'boolean':
        return (
          <FormControlLabel
            style={{ marginTop: 20, display: 'flex' }}
            control={(
              <Switch
                checked={defaultValue === 'true'}
                onChange={(_, checked) => setDefaultValue(checked ? 'true' : 'false')}
              />
            )}
            label={t_i18n('Default value')}
          />
        );
      case 'select':
      case 'multi_select':
        return (
          <MuiTextField
            select
            variant="standard"
            fullWidth
            label={t_i18n('Default value')}
            value={defaultValue}
            onChange={(event) => setDefaultValue(event.target.value)}
            style={{ marginTop: 20 }}
          >
            <MenuItem value="">{t_i18n('None')}</MenuItem>
            {(customField.select_options ?? []).map((option) => (
              <MenuItem key={option} value={option}>{option}</MenuItem>
            ))}
          </MuiTextField>
        );
      case 'integer':
        return (
          <MuiTextField
            type="number"
            variant="standard"
            fullWidth
            label={t_i18n('Default value')}
            value={defaultValue}
            onChange={(event) => setDefaultValue(event.target.value)}
            style={{ marginTop: 20 }}
          />
        );
      case 'date':
        return (
          <MuiTextField
            type="date"
            variant="standard"
            fullWidth
            label={t_i18n('Default value')}
            value={defaultValue}
            onChange={(event) => setDefaultValue(event.target.value)}
            slotProps={{ inputLabel: { shrink: true } }}
            style={{ marginTop: 20 }}
          />
        );
      case 'markdown':
        return (
          <MarkdownFieldBase
            name="default_value"
            label={t_i18n('Default value')}
            value={defaultValue}
            onValueChange={(nextValue) => setDefaultValue(nextValue)}
            style={{ marginTop: 20 }}
            height={200}
          />
        );
      default:
        return (
          <MuiTextField
            variant="standard"
            fullWidth
            label={t_i18n('Default value')}
            value={defaultValue}
            onChange={(event) => setDefaultValue(event.target.value)}
            style={{ marginTop: 20 }}
          />
        );
    }
  };

  return (
    <Dialog open={open} onClose={onClose} title={customField.label}>
      <FormControlLabel
        style={{ marginTop: 10, display: 'flex' }}
        control={(
          <Switch
            checked={mandatory}
            onChange={(_, checked) => setMandatory(checked)}
          />
        )}
        label={t_i18n('Mandatory')}
      />
      {renderDefaultValueField()}
      <DialogActions>
        <Button variant="secondary" onClick={onClose} disabled={submitting}>
          {t_i18n('Cancel')}
        </Button>
        <Button onClick={handleSubmit} disabled={submitting}>
          {t_i18n('Update')}
        </Button>
      </DialogActions>
    </Dialog>
  );
};

const EntitySettingCustomFieldsTable: FunctionComponent<EntitySettingCustomFieldsTableProps> = ({
  queryRef,
  entityType,
  refresh,
}) => {
  const { t_i18n } = useFormatter();
  const data = usePreloadedQuery(entitySettingCustomFieldsQuery, queryRef);
  const allCustomFields: CustomFieldDefinitionNode[] = (data.customFieldDefinitions?.edges ?? []).map((edge) => edge.node);
  const assignedCustomFields = allCustomFields.filter((cf) => (cf.entity_types ?? []).includes(entityType));

  const [editing, setEditing] = useState<CustomFieldDefinitionNode | null>(null);

  const [commitRemove] = useApiMutation(entitySettingCustomFieldsRemoveMutation);
  const handleRemove = (id: string) => {
    commitRemove({
      variables: { id, entityType },
      onCompleted: () => refresh(),
    });
  };

  return (
    <Table size="small">
      <TableHead>
        <TableRow>
          <TableCell>{t_i18n('Label')}</TableCell>
          <TableCell>{t_i18n('Technical name')}</TableCell>
          <TableCell>{t_i18n('Type')}</TableCell>
          <TableCell>{t_i18n('Mandatory')}</TableCell>
          <TableCell>{t_i18n('Default value')}</TableCell>
          <TableCell align="right" />
        </TableRow>
      </TableHead>
      <TableBody>
        {assignedCustomFields.map((cf) => {
          const setting = getEntityTypeSetting(cf, entityType);
          return (
            <TableRow key={cf.id}>
              <TableCell>{cf.label}</TableCell>
              <TableCell>{cf.name}</TableCell>
              <TableCell>{getCustomFieldTypeLabel(cf.field_type, t_i18n)}</TableCell>
              <TableCell>{setting?.mandatory ? t_i18n('Yes') : t_i18n('No')}</TableCell>
              <TableCell>{setting?.default_value ?? '-'}</TableCell>
              <TableCell align="right">
                <IconButton onClick={() => setEditing(cf)} aria-label={t_i18n('Update')}>
                  <EditOutlined fontSize="small" />
                </IconButton>
                <IconButton onClick={() => handleRemove(cf.id)} aria-label={t_i18n('Remove')}>
                  <DeleteOutlined fontSize="small" />
                </IconButton>
              </TableCell>
            </TableRow>
          );
        })}
        {assignedCustomFields.length === 0 && (
          <TableRow>
            <TableCell colSpan={6}>{t_i18n('No custom field for this entity type')}</TableCell>
          </TableRow>
        )}
      </TableBody>
      {editing && (
        <EntitySettingCustomFieldEditDialog
          customField={editing}
          entityType={entityType}
          open={editing !== null}
          onClose={() => setEditing(null)}
          onUpdated={refresh}
        />
      )}
    </Table>
  );
};

const EntitySettingCustomFields = () => {
  const { t_i18n } = useFormatter();
  const { subType } = useSubTypeOutletContext();
  const entityType = subType.id;
  const [addOpen, setAddOpen] = useState(false);
  const [queryRef, loadQuery] = useQueryLoadingWithLoadQuery<EntitySettingCustomFieldsQuery>(
    entitySettingCustomFieldsQuery,
    {},
  );
  const refresh = () => loadQuery({}, { fetchPolicy: 'network-only' });

  return (
    <Card
      title={t_i18n('Custom fields')}
      titleSx={{ alignItems: 'end' }}
      sx={{ paddingTop: 0, paddingBottom: 0, marginTop: 2 }}
      action={(
        <Button onClick={() => setAddOpen(true)}>
          {t_i18n('Add custom field')}
        </Button>
      )}
    >
      {queryRef && (
        <>
          <Suspense fallback={<Loader variant={LoaderVariant.inElement} />}>
            <EntitySettingCustomFieldsTable
              queryRef={queryRef}
              entityType={entityType}
              refresh={refresh}
            />
          </Suspense>
          <Suspense fallback={null}>
            <EntitySettingCustomFieldsAddDialog
              queryRef={queryRef}
              open={addOpen}
              onClose={() => setAddOpen(false)}
              entityType={entityType}
              onAdded={refresh}
            />
          </Suspense>
        </>
      )}
    </Card>
  );
};

export default EntitySettingCustomFields;
