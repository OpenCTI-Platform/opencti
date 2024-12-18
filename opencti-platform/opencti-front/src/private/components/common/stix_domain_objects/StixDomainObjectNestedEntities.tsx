import { IconButton, List, Typography } from '@mui/material';
import React, { FunctionComponent, useContext, useEffect } from 'react';
import { Add } from '@mui/icons-material';
import { useFormatter } from '../../../../components/i18n';
import Security from '../../../../utils/Security';
import { KNOWLEDGE_KNUPDATE } from '../../../../utils/hooks/useGranted';
import useHelper from '../../../../utils/hooks/useHelper';
import StixNestedRefRelationshipCreationFromEntity from '../stix_nested_ref_relationships/StixNestedRefRelationshipCreationFromEntity';
import { QueryRenderer } from '../../../../relay/environment';
import StixDomainObjectNestedEntitiesLines, { stixDomainObjectNestedEntitiesLinesQuery } from './StixDomainObjectNestedEntitiesLines';
import { StixDomainObjectNestedEntitiesLines_data$data } from './__generated__/StixDomainObjectNestedEntitiesLines_data.graphql';
import StixNestedRefRelationshipCreationFromEntityFabless from '../stix_nested_ref_relationships/StixNestedRefRelationshipCreationFromEntityFabless';
import { CreateRelationshipContext } from '../menus/CreateRelationshipContextProvider';

interface StixDomainObjectNestedEntitiesProps {
  entityId: string,
  entityType: string,
  targetStixCoreObjectTypes: string[],
}

const StixDomainObjectNestedEntities: FunctionComponent<
StixDomainObjectNestedEntitiesProps
> = ({
  entityId,
  entityType,
  targetStixCoreObjectTypes,
}) => {
  const { t_i18n } = useFormatter();
  const { setState } = useContext(CreateRelationshipContext);
  const { isFeatureEnable } = useHelper();
  const isFABReplaced = isFeatureEnable('FAB_REPLACEMENT');

  const paginationOptions = {
    fromOrToId: entityId,
    search: '',
    orderBy: null,
    orderMode: 'desc',
  };

  useEffect(() => setState({
    paginationOptions,
  }), []);

  return (
    <div style={{ marginTop: 20 }}>
      <Typography variant="h4" gutterBottom={true} style={{ float: 'left' }}>
        {t_i18n('Nested objects')}
      </Typography>
      <Security
        needs={[KNOWLEDGE_KNUPDATE]}
        placeholder={<div style={{ height: 29 }} />}
      >
        {isFABReplaced
          ? (
            <StixNestedRefRelationshipCreationFromEntityFabless
              id={entityId}
              targetStixCoreObjectTypes={targetStixCoreObjectTypes}
              controlledDial={({ onOpen }) => (
                <IconButton
                  color="primary"
                  aria-label="Label"
                  onClick={onOpen}
                  style={{ float: 'left', margin: '-15px 0 0 -2px' }}
                  size="large"
                >
                  <Add fontSize="small" />
                </IconButton>
              )}
            />
          )
          : (
            <StixNestedRefRelationshipCreationFromEntity
              paginationOptions={paginationOptions}
              entityId={entityId}
              variant="inLine"
              entityType={entityType}
              targetStixCoreObjectTypes={targetStixCoreObjectTypes}
              isRelationReversed={false}
            />
          )
        }
      </Security>
      <div className="clearfix" />
      <List style={{ marginTop: -10 }}>
        <QueryRenderer
          query={stixDomainObjectNestedEntitiesLinesQuery}
          variables={{ count: 25, ...paginationOptions }}
          render={({ props }: { props: StixDomainObjectNestedEntitiesLines_data$data }) => (
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
