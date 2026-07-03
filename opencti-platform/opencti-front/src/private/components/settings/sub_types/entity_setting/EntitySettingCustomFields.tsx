import Card from '@common/card/Card';
import Button from '@common/button/Button';
import IconButton from '@common/button/IconButton';
import DeleteOutlined from '@mui/icons-material/DeleteOutlined';
import Table from '@mui/material/Table';
import TableBody from '@mui/material/TableBody';
import TableCell from '@mui/material/TableCell';
import TableHead from '@mui/material/TableHead';
import TableRow from '@mui/material/TableRow';
import { FunctionComponent, Suspense, useState } from 'react';
import { graphql, PreloadedQuery, usePreloadedQuery } from 'react-relay';
import Loader, { LoaderVariant } from '../../../../../components/Loader';
import { useFormatter } from '../../../../../components/i18n';
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
          mandatory
          entity_types
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
    default:
      return t_i18n('Text');
  }
};

interface EntitySettingCustomFieldsTableProps {
  queryRef: PreloadedQuery<EntitySettingCustomFieldsQuery>;
  entityType: string;
  refresh: () => void;
}

const EntitySettingCustomFieldsTable: FunctionComponent<EntitySettingCustomFieldsTableProps> = ({
  queryRef,
  entityType,
  refresh,
}) => {
  const { t_i18n } = useFormatter();
  const data = usePreloadedQuery(entitySettingCustomFieldsQuery, queryRef);
  const allCustomFields: CustomFieldDefinitionNode[] = (data.customFieldDefinitions?.edges ?? []).map((edge) => edge.node);
  const assignedCustomFields = allCustomFields.filter((cf) => (cf.entity_types ?? []).includes(entityType));

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
          <TableCell align="right" />
        </TableRow>
      </TableHead>
      <TableBody>
        {assignedCustomFields.map((cf) => (
          <TableRow key={cf.id}>
            <TableCell>{cf.label}</TableCell>
            <TableCell>{cf.name}</TableCell>
            <TableCell>{getCustomFieldTypeLabel(cf.field_type, t_i18n)}</TableCell>
            <TableCell>{cf.mandatory ? t_i18n('Yes') : t_i18n('No')}</TableCell>
            <TableCell align="right">
              <IconButton onClick={() => handleRemove(cf.id)} aria-label={t_i18n('Remove')}>
                <DeleteOutlined fontSize="small" />
              </IconButton>
            </TableCell>
          </TableRow>
        ))}
        {assignedCustomFields.length === 0 && (
          <TableRow>
            <TableCell colSpan={5}>{t_i18n('No custom field for this entity type')}</TableCell>
          </TableRow>
        )}
      </TableBody>
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
