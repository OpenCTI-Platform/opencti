import React, { FunctionComponent, useContext, useEffect, useState } from 'react';
import { Add, ArrowDropDown, ArrowDropUp } from '@mui/icons-material';
import { IconButton, List, ListItem, ListItemIcon, ListItemSecondaryAction, ListItemText, Paper, Typography } from '@mui/material';
import { useFormatter } from '../../../../components/i18n';
import { CreateRelationshipContext } from '../../common/menus/CreateRelationshipContextProvider';
import useHelper from '../../../../utils/hooks/useHelper';
import Security from '../../../../utils/Security';
import { KNOWLEDGE_KNUPDATE } from '../../../../utils/hooks/useGranted';
import StixNestedRefRelationshipCreationFromEntity from '../../common/stix_nested_ref_relationships/StixNestedRefRelationshipCreationFromEntity';
import SearchInput from '../../../../components/SearchInput';
import { QueryRenderer } from '../../../../relay/environment';
import StixCyberObservableNestedEntitiesLines, { stixCyberObservableNestedEntitiesLinesQuery } from './StixCyberObservableNestedEntitiesLines';
import { StixCyberObservableNestedEntitiesLines_data$data } from './__generated__/StixCyberObservableNestedEntitiesLines_data.graphql';
import StixNestedRefRelationshipCreationFromEntityFabless from '../../common/stix_nested_ref_relationships/StixNestedRefRelationshipCreationFromEntityFabless';

interface StixCyberObservableNestedEntitiesProps {
  entityId: string,
  entityType: string,
  targetStixCoreObjectTypes: string[],
}

const StixCyberObservableNestedEntities: FunctionComponent<
StixCyberObservableNestedEntitiesProps
> = ({
  entityId,
  entityType,
  targetStixCoreObjectTypes,
}) => {
  const { t_i18n } = useFormatter();
  const { setState } = useContext(CreateRelationshipContext);
  const { isFeatureEnable } = useHelper();
  const isFABReplaced = isFeatureEnable('FAB_REPLACEMENT');
  const [sortBy, setSortBy] = useState<string>();
  const [orderAsc, setOrderAsc] = useState<boolean>(false);
  const [searchTerm, setSearchTerm] = useState<string>('');

  const handleSort = (field: string) => {
    setSortBy(field);
    setOrderAsc(!orderAsc);
  };
  const handleSearch = (term: string) => setSearchTerm(term);

  const sortHeader = (field: string, label: string, isSortable: boolean) => {
    const fieldWidths: Record<string, string> = {
      relationship_type: '10%',
      entity_type: '10%',
      name: '22%',
      creator: '12%',
      start_time: '15%',
      stop_time: '15%',
    };
    const SortComponentStyles: React.CSSProperties = {
      position: 'absolute',
      margin: '0 0 0 5px',
      padding: 0,
      top: '0px',
    };
    const SortComponent = orderAsc
      ? (<ArrowDropDown style={SortComponentStyles} />)
      : (<ArrowDropUp style={SortComponentStyles} />);
    return (
      <div
        style={{
          float: 'left',
          fontSize: 12,
          fontWeight: '700',
          whiteSpace: 'nowrap',
          overflow: 'hidden',
          textOverflow: 'ellipsis',
          paddingRight: 10,
          width: fieldWidths[field],
          cursor: isSortable ? 'pointer' : undefined,
          textTransform: 'uppercase',
        }}
        onClick={isSortable ? () => handleSort(field) : undefined}
      >
        <span>{t_i18n(label)}</span>
        {sortBy === field ? SortComponent : ''}
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
          )
          : (
            <StixNestedRefRelationshipCreationFromEntity
              paginationOptions={paginationOptions}
              entityId={entityId}
              entityType={entityType}
              variant="inLine"
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
        variant="outlined"
        style={{
          margin: 0,
          padding: 15,
          borderRadius: 4,
        }}
      >
        <List style={{ marginTop: -10 }}>
          <ListItem
            divider={false}
            style={{
              paddingTop: 0,
              paddingLeft: 10,
              textTransform: 'uppercase',
            }}
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
                  {sortHeader('relationship_type', 'Attribute', true)}
                  {sortHeader('entity_type', 'Entity type', false)}
                  {sortHeader('name', 'Name', false)}
                  {sortHeader('creator', 'Creator', false)}
                  {sortHeader('start_time', 'First obs.', true)}
                  {sortHeader('stop_time', 'Last obs.', true)}
                </div>
              }
            />
            <ListItemSecondaryAction> &nbsp; </ListItemSecondaryAction>
          </ListItem>
          <QueryRenderer
            query={stixCyberObservableNestedEntitiesLinesQuery}
            variables={{ count: 200, ...paginationOptions }}
            render={({ props }: { props: StixCyberObservableNestedEntitiesLines_data$data }) => (
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
