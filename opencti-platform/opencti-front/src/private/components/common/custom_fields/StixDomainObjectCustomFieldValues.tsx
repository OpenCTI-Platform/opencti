import { Suspense } from 'react';
import { graphql, useLazyLoadQuery } from 'react-relay';
import useHelper from '../../../../utils/hooks/useHelper';
import CustomFieldValuesDisplay from './CustomFieldValuesDisplay';
import { StixDomainObjectCustomFieldValuesQuery } from './__generated__/StixDomainObjectCustomFieldValuesQuery.graphql';

const query = graphql`
  query StixDomainObjectCustomFieldValuesQuery($id: String!) {
    stixDomainObject(id: $id) {
      entity_type
      customFieldValues {
        field_id
        field_name
        int_value
        string_value
        boolean_value
        date_value
        select_value
        select_values
      }
    }
  }
`;

const CustomFieldValues = ({ entityId }: { entityId: string }) => {
  const { stixDomainObject } = useLazyLoadQuery<StixDomainObjectCustomFieldValuesQuery>(query, { id: entityId });
  if (!stixDomainObject) return null;
  return <CustomFieldValuesDisplay entityType={stixDomainObject.entity_type} values={stixDomainObject.customFieldValues ?? []} />;
};

// The shared overview receives plain objects from many fragments; own its data requirements here.
const StixDomainObjectCustomFieldValues = ({ entityId }: { entityId: string }) => {
  const { isFeatureEnable } = useHelper();
  if (!isFeatureEnable('CUSTOM_FIELDS')) return null;
  return <Suspense fallback={null}><CustomFieldValues entityId={entityId} /></Suspense>;
};

export default StixDomainObjectCustomFieldValues;
