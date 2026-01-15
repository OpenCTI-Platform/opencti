import React from 'react';
import Typography from '@mui/material/Typography';
import List from '@mui/material/List';
import StixNestedRefRelationshipCreationFromEntityContainer from '../stix_nested_ref_relationships/StixNestedRefRelationshipCreationFromEntityContainer';
import { useFormatter } from '../../../../components/i18n';
import Security from '../../../../utils/Security';
import { KNOWLEDGE_KNUPDATE } from '../../../../utils/hooks/useGranted';
import { QueryRenderer } from '../../../../relay/environment';
import StixDomainObjectNestedEntitiesLines, { stixDomainObjectNestedEntitiesLinesQuery } from './StixDomainObjectNestedEntitiesLines';

const StixDomainObjectNestedEntities = ({
  entityId,
  entityType,
}) => {
  const { t_i18n } = useFormatter();

  const paginationOptions = {
    fromOrToId: entityId,
    search: '',
    orderBy: null,
    orderMode: 'desc',
  };
  return (
    <div style={{ marginTop: 20 }}>
      <Typography variant="h4" gutterBottom={true} style={{ float: 'left' }}>
        {t_i18n('Nested objects')}
      </Typography>
      <Security
        needs={[KNOWLEDGE_KNUPDATE]}
        placeholder={<div style={{ height: 29 }} />}
      >
        <StixNestedRefRelationshipCreationFromEntityContainer
          paginationOptions={paginationOptions}
          entityId={entityId}
          variant="inLine"
          entityType={entityType}
        />
      </Security>
      <div className="clearfix" />
      <List style={{ marginTop: -10 }}>
        <QueryRenderer
          query={stixDomainObjectNestedEntitiesLinesQuery}
          variables={{ count: 25, ...paginationOptions }}
          render={({ props }) => (
            <StixDomainObjectNestedEntitiesLines
              stixDomainObjectId={entityId}
              paginationOptions={paginationOptions}
              data={props}
            />
          )}
        />
      </List>
    </div>
  );
};

export default StixDomainObjectNestedEntities;
