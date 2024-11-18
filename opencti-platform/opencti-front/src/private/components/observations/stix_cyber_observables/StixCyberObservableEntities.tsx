import React, { FunctionComponent, useContext, useEffect, useState } from 'react';
import { Add, ArrowDropDown, ArrowDropUp } from '@mui/icons-material';
import { IconButton, List, ListItem, ListItemIcon, ListItemSecondaryAction, ListItemText, Paper, Typography } from '@mui/material';
import { useFormatter } from '../../../../components/i18n';
import { CreateRelationshipContext } from '../../common/menus/CreateRelationshipContextProvider';
import useHelper from '../../../../utils/hooks/useHelper';
import Security from '../../../../utils/Security';
import { KNOWLEDGE_KNUPDATE } from '../../../../utils/hooks/useGranted';
import StixCoreRelationshipCreationFromControlledDial from '../../common/stix_core_relationships/StixCoreRelationshipCreationFromControlledDial';
import StixCoreRelationshipCreationFromEntity from '../../common/stix_core_relationships/StixCoreRelationshipCreationFromEntity';
import SearchInput from '../../../../components/SearchInput';
import { QueryRenderer } from '../../../../relay/environment';
import StixCyberObservableEntitiesLines, { stixCyberObservableEntitiesLinesQuery } from './StixCyberObservableEntitiesLines';
import { StixCyberObservableEntitiesLinesPaginationQuery$data } from './__generated__/StixCyberObservableEntitiesLinesPaginationQuery.graphql';

interface StixCyberObservableEntitiesProps {
  entityId: string;
  defaultStartTime: string;
  defaultStopTime: string;
}

const StixCyberObservableEntities: FunctionComponent<StixCyberObservableEntitiesProps> = ({
  entityId,
  defaultStartTime,
  defaultStopTime,
}) => {
  const { t_i18n } = useFormatter();
  const { setState } = useContext(CreateRelationshipContext);
  const { isFeatureEnable } = useHelper();
  const isFABReplaced = isFeatureEnable('FAB_REPLACEMENT');

  const [sortBy, setSortBy] = useState<string>();
  const [orderAsc, setOrderAsc] = useState<boolean>(false);
  const [searchTerm, setSearchTerm] = useState<string>('');
  const [relationReversed, setRelationReversed] = useState<boolean>(false);

  const handleSort = (field: string) => {
    setSortBy(field);
    setOrderAsc(!orderAsc);
  };
  const handleSearch = (term: string) => setSearchTerm(term);
  const handleReverseRelation = () => setRelationReversed(!relationReversed);
  const sortHeader = (field: string, label: string, isSortable: boolean) => {
    const fieldWidths: Record<string, string> = {
      relationship_type: '10%',
      entity_type: '10%',
      name: '22%',
      createdBy: '12%',
      creator: '12%',
      start_time: '10%',
      stop_time: '10%',
      confidence: '12%',
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
        {t_i18n('Relations')}
      </Typography>
      <Security
        needs={[KNOWLEDGE_KNUPDATE]}
        placeholder={<div style={{ height: 29 }} />}
      >
        {isFABReplaced
          ? (
            <StixCoreRelationshipCreationFromControlledDial
              entityId={entityId}
              defaultStartTime={defaultStartTime}
              defaultStopTime={defaultStopTime}
              isReversable={true}
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
            <StixCoreRelationshipCreationFromEntity
              paginationOptions={paginationOptions}
              handleReverseRelation={handleReverseRelation}
              entityId={entityId}
              variant="inLine"
              isRelationReversed={relationReversed}
              targetStixDomainObjectTypes={['Stix-Domain-Object']}
              targetStixCyberObservableTypes={['Stix-Cyber-Observable']}
              defaultStartTime={defaultStartTime}
              defaultStopTime={defaultStopTime}
              paddingRight={0}
            />
          )
        }
      </Security>
      <div
        style={{
          float: 'right',
          marginTop: -10,
        }}
      >
        <SearchInput
          variant="thin"
          onSubmit={handleSearch}
          keyword={searchTerm}
        />
      </div>
      <div className="clearfix" />
      <Paper variant="outlined">
        <List
          style={{
            height: '100%',
            minHeight: '100%',
            margin: 0,
            padding: '23px 7px 23px 7px',
            borderRadius: 4,
            marginTop: -10,
          }}
        >
          <ListItem style={{ paddingTop: 0 }} divider={false}>
            <ListItemIcon
              style={{
                padding: '0 8px 0 8px',
                fontWeight: 700,
                fontSize: 12,
              }}
            >
              &nbsp;
            </ListItemIcon>
            <ListItemText
              primary={<div>
                {sortHeader('relationship_type', 'Relationship', true)}
                {sortHeader('entity_type', 'Entity Type', false)}
                {sortHeader('name', 'Name', false)}
                {sortHeader('createdBy', 'Author', false)}
                {sortHeader('creator', 'Creator', false)}
                {sortHeader('start_time', 'First obs.', true)}
                {sortHeader('stop_time', 'Last obs.', true)}
                {sortHeader('confidence', 'Confidence level', true)}
              </div>}
            />
            <ListItemSecondaryAction> &nbsp; </ListItemSecondaryAction>
          </ListItem>
          <QueryRenderer
            query={stixCyberObservableEntitiesLinesQuery}
            variables={{ count: 200, ...paginationOptions }}
            render={({ props }: { props: StixCyberObservableEntitiesLinesPaginationQuery$data }) => (
              <StixCyberObservableEntitiesLines
                data={props}
                paginationOptions={paginationOptions}
                displayRelation={true}
                stixCyberObservableId={entityId}
              />
            )}
          />
        </List>
      </Paper>
    </div>
  );
};

export default StixCyberObservableEntities;
