import { IconButton, List, ListItem, ListItemIcon, ListItemSecondaryAction, ListItemText, Paper, Typography } from '@mui/material';
import React, { FunctionComponent, useContext, useEffect, useState } from 'react';
import { Add, ArrowDropDown, ArrowDropUp } from '@mui/icons-material';
import { useFormatter } from '../../../../components/i18n';
import Security from '../../../../utils/Security';
import { KNOWLEDGE_KNUPDATE } from '../../../../utils/hooks/useGranted';
import StixNestedRefRelationshipCreationFromEntity from '../../common/stix_nested_ref_relationships/StixNestedRefRelationshipCreationFromEntity';
import SearchInput from '../../../../components/SearchInput';
import { QueryRenderer } from '../../../../relay/environment';
import StixCyberObservableNestedEntitiesLines, { stixCyberObservableNestedEntitiesLinesQuery } from './StixCyberObservableNestedEntitiesLines';
import { StixCyberObservableNestedEntitiesLinesQuery$data } from './__generated__/StixCyberObservableNestedEntitiesLinesQuery.graphql';
import { CreateRelationshipContext } from '../../common/menus/CreateRelationshipContextProvider';
import useHelper from '../../../../utils/hooks/useHelper';
import StixNestedRefRelationshipCreationFromEntityFabless from '../../common/stix_nested_ref_relationships/StixNestedRefRelationshipCreationFromEntityFabless';

const inlineStylesHeaders: Record<string, React.CSSProperties> = {
  relationship_type: {
    float: 'left',
    width: '10%',
    fontSize: 12,
    fontWeight: '700',
    cursor: 'pointer',
    whiteSpace: 'nowrap',
    overflow: 'hidden',
    textOverflow: 'ellipsis',
    paddingRight: 10,
  },
  entity_type: {
    float: 'left',
    width: '10%',
    fontSize: 12,
    fontWeight: '700',
    whiteSpace: 'nowrap',
    overflow: 'hidden',
    textOverflow: 'ellipsis',
    paddingRight: 10,
  },
  name: {
    float: 'left',
    width: '22%',
    fontSize: 12,
    fontWeight: '700',
    whiteSpace: 'nowrap',
    overflow: 'hidden',
    textOverflow: 'ellipsis',
    paddingRight: 10,
  },
  creator: {
    float: 'left',
    width: '12%',
    fontSize: 12,
    fontWeight: '700',
    whiteSpace: 'nowrap',
    overflow: 'hidden',
    textOverflow: 'ellipsis',
    paddingRight: 10,
  },
  start_time: {
    float: 'left',
    width: '15%',
    fontSize: 12,
    fontWeight: '700',
    cursor: 'pointer',
    whiteSpace: 'nowrap',
    overflow: 'hidden',
    textOverflow: 'ellipsis',
    paddingRight: 10,
  },
  stop_time: {
    float: 'left',
    width: '15%',
    fontSize: 12,
    fontWeight: '700',
    cursor: 'pointer',
    whiteSpace: 'nowrap',
    overflow: 'hidden',
    textOverflow: 'ellipsis',
    paddingRight: 10,
  },
};

interface StixCyberObservableNestedEntitiesProps {
  entityId: string,
  entityType: string,
  targetStixCoreObjectTypes?: string[],
}

const StixCyberObservableNestedEntities: FunctionComponent<
StixCyberObservableNestedEntitiesProps
> = ({
  entityId,
  entityType,
  targetStixCoreObjectTypes = [],
}) => {
  const { t_i18n } = useFormatter();
  const { setState } = useContext(CreateRelationshipContext);
  const { isFeatureEnable } = useHelper();
  const isFABReplaced = isFeatureEnable('FAB_REPLACEMENT');
  const [searchTerm, setSearchTerm] = useState<string>('');
  const [sortBy, setSortBy] = useState<string | null>(null);
  const [orderAsc, setOrderAsc] = useState<boolean>(false);

  const handleSort = (field: string, updatedOrder: boolean) => {
    setSortBy(field);
    setOrderAsc(updatedOrder);
  };

  const handleSearch = (value: string) => setSearchTerm(value);

  const SortHeader = (field: string, label: string, isSortable: boolean) => {
    const sortComponent = orderAsc ? (
      <ArrowDropDown
        style={{
          position: 'absolute',
          margin: '0 0 0 5px',
          padding: 0,
          top: '0px',
        }}
      />
    ) : (
      <ArrowDropUp
        style={{
          position: 'absolute',
          margin: '0 0 0 5px',
          padding: 0,
          top: '0px',
        }}
      />
    );
    if (isSortable) {
      return (
        <div
          style={inlineStylesHeaders[field]}
          onClick={() => handleSort(field, !orderAsc)}
        >
          <span>{t_i18n(label)}</span>
          {sortBy === field ? sortComponent : ''}
        </div>
      );
    }
    return (
      <div style={inlineStylesHeaders[field]}>
        <span>{t_i18n(label)}</span>
      </div>
    );
  };

  const paginationOptions = {
    fromOrToId: entityId,
    search: searchTerm,
    orderBy: sortBy,
    orderMode: orderAsc ? 'asc' : 'desc',
  };

  useEffect(() => setState({
    paginationOptions,
  }), []);

  return (
    <div style={{ height: '100%' }}>
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
      <div style={{ float: 'right', marginTop: -10 }}>
        <SearchInput
          variant="thin"
          onSubmit={handleSearch}
          keyword={searchTerm}
        />
      </div>
      <div className="clearfix" />
      <Paper
        style={{
          margin: 0,
          padding: 15,
          borderRadius: 4,
        }}
        variant="outlined"
      >
        <List style={{ marginTop: -10 }}>
          <ListItem
            style={{
              paddingLeft: 10,
              paddingTop: 0,
              textTransform: 'uppercase',
            }}
            divider={false}
          >
            <ListItemIcon>
              <span
                style={{
                  padding: '0 8px 0 8px',
                  fontWeight: 700,
                  fontSize: 12,
                }}
              >
                &nbsp;
              </span>
            </ListItemIcon>
            <ListItemText
              primary={
                <div>
                  {SortHeader('relationship_type', 'Attribute', true)}
                  {SortHeader('entity_type', 'Entity type', false)}
                  {SortHeader('name', 'Name', false)}
                  {SortHeader('creator', 'Creator', false)}
                  {SortHeader('start_time', 'First obs.', true)}
                  {SortHeader('stop_time', 'Last obs.', true)}
                </div>
              }
            />
            <ListItemSecondaryAction> &nbsp; </ListItemSecondaryAction>
          </ListItem>
          <QueryRenderer
            query={stixCyberObservableNestedEntitiesLinesQuery}
            variables={{ count: 200, ...paginationOptions }}
            render={({ props }: { props: StixCyberObservableNestedEntitiesLinesQuery$data }) => (
              <StixCyberObservableNestedEntitiesLines
                stixCyberObservableId={entityId}
                paginationOptions={paginationOptions}
                data={props}
              />
            )}
          />
        </List>
      </Paper>
    </div>
  );
};

export default StixCyberObservableNestedEntities;
