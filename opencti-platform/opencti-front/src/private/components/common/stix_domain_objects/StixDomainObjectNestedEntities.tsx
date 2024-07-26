import { IconButton, List, styled, Typography } from '@mui/material';
import React, { FunctionComponent, useContext, useEffect } from 'react';
import { useFormatter } from 'src/components/i18n';
import Security from 'src/utils/Security';
import { KNOWLEDGE_KNUPDATE } from 'src/utils/hooks/useGranted';
import useHelper from 'src/utils/hooks/useHelper';
import { QueryRenderer } from 'src/relay/environment';
import { Add } from '@mui/icons-material';
import StixNestedRefRelationshipCreationFromEntityFabless from '../stix_nested_ref_relationships/StixNestedRefRelationshipCreationFromEntityFabless';
import { CreateRelationshipContext } from '../menus/CreateRelationshipContextProvider';
import StixNestedRefRelationshipCreationFromEntity from '../stix_nested_ref_relationships/StixNestedRefRelationshipCreationFromEntity';
import StixDomainObjectNestedEntitiesLines, { stixDomainObjectNestedEntitiesLinesQuery } from './StixDomainObjectNestedEntitiesLines';
import { StixDomainObjectNestedEntitiesLines_data$data } from './__generated__/StixDomainObjectNestedEntitiesLines_data.graphql';

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

  const StyledContainer = styled('div')({ marginTop: 20 });

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
    <StyledContainer>
      <Typography variant="h4" gutterBottom={true} style={{ float: 'left' }}>
        {t_i18n('Nested objects')}
      </Typography>
      <Security
        needs={[KNOWLEDGE_KNUPDATE]}
        placeholder={<div style={{ height: 29 }} />}
      >
        {isFABReplaced
          ? <StixNestedRefRelationshipCreationFromEntityFabless
              id={entityId}
              entityType={entityType}
              isReversable={false}
              controlledDial={({ onOpen }) => {
                return (
                  <IconButton
                    color="primary"
                    aria-label={t_i18n('Label')}
                    onClick={onOpen}
                    size="large"
                    style={{
                      float: 'left',
                      margin: '-15px 0 0 -2px',
                    }}
                  >
                    <Add fontSize="small" />
                  </IconButton>
                );
              }}
            />
          : <StixNestedRefRelationshipCreationFromEntity
              paginationOptions={paginationOptions}
              entityId={entityId}
              variant="inLine"
              entityType={entityType}
              targetStixCoreObjectTypes={targetStixCoreObjectTypes}
              isRelationReversed={false}
            />
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
    </StyledContainer>
  );
};

export default StixDomainObjectNestedEntities;
