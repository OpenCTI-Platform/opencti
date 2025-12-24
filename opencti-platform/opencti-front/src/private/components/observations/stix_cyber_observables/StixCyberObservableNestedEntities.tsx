import React, { useState } from 'react';
import StixNestedRefRelationshipCreationFromEntityContainer from '@components/common/stix_nested_ref_relationships/StixNestedRefRelationshipCreationFromEntityContainer';
import Security from '../../../../utils/Security';
import { KNOWLEDGE_KNUPDATE } from '../../../../utils/hooks/useGranted';
import SearchInput from '../../../../components/SearchInput';
import StixCyberObservableNestedEntitiesTable from './StixCyberObservableNestedEntitiesTable';
import { useFormatter } from '../../../../components/i18n';
import Card from '../../../../components/common/card/Card';

interface StixCyberObservableNestedEntitiesProps {
  entityId: string;
  entityType: string;
  variant?: 'inLine' | undefined;
}

const StixCyberObservableNestedEntities: React.FC<StixCyberObservableNestedEntitiesProps> = ({
  entityId,
  entityType,
  variant,
}) => {
  const { t_i18n } = useFormatter();
  const [searchTerm, setSearchTerm] = useState('');
  const isInLine = variant === 'inLine';

  const handleSearch = (value: string) => {
    setSearchTerm(value);
  };

  const paginationOptions = {
    fromOrToId: entityId,
    search: searchTerm,
    orderBy: isInLine ? 'relationship_type' : null,
    orderMode: 'desc',
  };

  return (
    <div style={{ height: isInLine ? 'auto' : '100%' }}>
      <Card
        title={t_i18n('Nested objects')}
        action={(
          <div>
            <Security needs={[KNOWLEDGE_KNUPDATE]}>
              <StixNestedRefRelationshipCreationFromEntityContainer
                paginationOptions={paginationOptions}
                entityId={entityId}
                variant="inLine"
                entityType={entityType}
              />
            </Security>
            {!isInLine && (
              <SearchInput
                variant="thin"
                onSubmit={handleSearch}
                keyword={searchTerm}
              />
            )}
          </div>
        )}
      >
        <StixCyberObservableNestedEntitiesTable
          stixCyberObservableId={entityId}
          searchTerm={searchTerm}
          isInLine={isInLine}
        />
      </Card>
    </div>
  );
};

export default StixCyberObservableNestedEntities;
