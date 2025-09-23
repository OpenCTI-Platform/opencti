import React, { useState } from 'react';
import Typography from '@mui/material/Typography';
import Paper from '@mui/material/Paper';
import StixNestedRefRelationshipCreationFromEntityContainer from '@components/common/stix_nested_ref_relationships/StixNestedRefRelationshipCreationFromEntityContainer';
import Security from '../../../../utils/Security';
import { KNOWLEDGE_KNUPDATE } from '../../../../utils/hooks/useGranted';
import SearchInput from '../../../../components/SearchInput';
import StixCyberObservableNestedEntitiesTable from './StixCyberObservableNestedEntitiesTable';
import { useFormatter } from '../../../../components/i18n';

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
      <Typography
        variant={isInLine ? 'h3' : 'h4'}
        gutterBottom={true}
        style={{ float: 'left' }}
      >
        {t_i18n('Nested objects')}
      </Typography>
      <Security
        needs={[KNOWLEDGE_KNUPDATE]}
        placeholder={<div style={{ height: 29 }}/>}
      >
        <StixNestedRefRelationshipCreationFromEntityContainer
          paginationOptions={paginationOptions}
          entityId={entityId}
          variant="inLine"
          entityType={entityType}
        />
      </Security>
      {!isInLine && (
        <>
          <div style={{ float: 'right', marginTop: -10 }}>
            <SearchInput
              variant="thin"
              onSubmit={handleSearch}
              keyword={searchTerm}
            />
          </div>
          <div className="clearfix"/>
        </>
      )}
      <Paper
        style={{
          margin: 0,
          padding: isInLine ? 0 : 15,
          borderRadius: 4,
        }}
        elevation={0}
        variant={isInLine ? undefined : 'outlined'}
      >
        <StixCyberObservableNestedEntitiesTable
          stixCyberObservableId={entityId}
          searchTerm={searchTerm}
          isInLine={isInLine}
        />
      </Paper>
    </div>
  );
};

export default StixCyberObservableNestedEntities;
