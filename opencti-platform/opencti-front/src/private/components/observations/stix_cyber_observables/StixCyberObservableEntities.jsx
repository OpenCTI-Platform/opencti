import React, { useState } from 'react';
import * as PropTypes from 'prop-types';
import withStyles from '@mui/styles/withStyles';
import List from '@mui/material/List';
import ListItem from '@mui/material/ListItem';
import ListItemIcon from '@mui/material/ListItemIcon';
import ListItemText from '@mui/material/ListItemText';
import { ArrowDropDown, ArrowDropUp } from '@mui/icons-material';
import Card from '@common/card/Card';
import { QueryRenderer } from '../../../../relay/environment';
import { useFormatter } from '../../../../components/i18n';
import StixCyberObservableEntitiesLines, { stixCyberObservableEntitiesLinesQuery } from './StixCyberObservableEntitiesLines';
import StixCoreRelationshipCreationFromEntity from '../../common/stix_core_relationships/StixCoreRelationshipCreationFromEntity';
import Security from '../../../../utils/Security';
import { KNOWLEDGE_KNUPDATE } from '../../../../utils/hooks/useGranted';
import SearchInput from '../../../../components/SearchInput';
import { Stack } from '@mui/material';

const styles = (theme) => ({
  paper: {
    margin: 0,
    padding: 15,
    borderRadius: 4,
  },
  item: {
    paddingLeft: 10,
    height: 50,
  },
  itemIcon: {
    color: theme.palette.primary.main,
  },
  itemHead: {
    paddingLeft: 10,
    textTransform: 'uppercase',
  },
  bodyItem: {
    height: 25,
    fontSize: 13,
    float: 'left',
    whiteSpace: 'nowrap',
    overflow: 'hidden',
    textOverflow: 'ellipsis',
    paddingRight: 10,
  },
  goIcon: {
    position: 'absolute',
    right: -10,
  },
  itemIconDisabled: {
    color: theme.palette.grey[700],
  },
  placeholder: {
    display: 'inline-block',
    height: '1em',
    backgroundColor: theme.palette.grey[700],
  },
});

const inlineStylesHeaders = {
  iconSort: {
    position: 'absolute',
    margin: '0 0 0 5px',
    padding: 0,
    top: '0px',
  },
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
  entity_tyoe: {
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
  createdBy: {
    float: 'left',
    width: '12%',
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
    width: '10%',
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
    width: '10%',
    fontSize: 12,
    fontWeight: '700',
    cursor: 'pointer',
    whiteSpace: 'nowrap',
    overflow: 'hidden',
    textOverflow: 'ellipsis',
    paddingRight: 10,
  },
  confidence: {
    float: 'left',
    width: '12%',
    fontSize: 12,
    fontWeight: '700',
    cursor: 'pointer',
    whiteSpace: 'nowrap',
    overflow: 'hidden',
    textOverflow: 'ellipsis',
    paddingRight: 10,
  },
};

const StixCyberObservableEntities = (props) => {
  const { t_i18n } = useFormatter();
  const [sortBy, setSortBy] = useState(null);
  const [orderAsc, setOrderAsc] = useState(false);
  const [searchTerm, setSearchTerm] = useState('');
  const [relationReversed, setRelationReversed] = useState(false);
  const handleReverseRelation = () => {
    setRelationReversed(!relationReversed);
  };

  const handleSort = (field, orderAsc) => {
    setSortBy(field);
    setOrderAsc(orderAsc);
  };

  const handleSearch = (value) => {
    setSearchTerm(value);
  };

  const SortHeader = (field, label, isSortable) => {
    const sortComponent = orderAsc ? (
      <ArrowDropDown style={inlineStylesHeaders.iconSort} />
    ) : (
      <ArrowDropUp style={inlineStylesHeaders.iconSort} />
    );
    if (isSortable) {
      return (
        <div
          style={inlineStylesHeaders[field]}
          onClick={handleSort.bind(null, field, !orderAsc)}
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

  const { classes, entityId, defaultStartTime, defaultStopTime } = props;
  const paginationOptions = {
    fromOrToId: entityId,
    search: searchTerm,
    orderBy: sortBy,
    orderMode: orderAsc ? 'asc' : 'desc',
  };
  return (
    <div style={{ height: '100%' }}>
      <Card
        title={t_i18n('Relations')}
        action={(
          <Stack direction="row" gap={1}>
            <Security needs={[KNOWLEDGE_KNUPDATE]}>
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
              />
            </Security>
            <SearchInput
              variant="thin"
              onSubmit={handleSearch}
              keyword={searchTerm}
            />
          </Stack>
        )}
      >
        <List style={{ marginTop: -10 }}>
          <ListItem
            classes={{ root: classes.itemHead }}
            divider={false}
            style={{ paddingTop: 0 }}
            secondaryAction={<> &nbsp; </>}
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
              primary={(
                <div>
                  {SortHeader('relationship_type', 'Relationship', true)}
                  {SortHeader('entity_tyoe', 'Entity type', false)}
                  {SortHeader('name', 'Name', false)}
                  {SortHeader('createdBy', 'Author', false)}
                  {SortHeader('creator', 'Creator', false)}
                  {SortHeader('start_time', 'Start time', true)}
                  {SortHeader('stop_time', 'Stop time', true)}
                  {SortHeader('confidence', 'Confidence level', true)}
                </div>
              )}
            />
          </ListItem>
          <QueryRenderer
            query={stixCyberObservableEntitiesLinesQuery}
            variables={{ count: 200, ...paginationOptions }}
            render={({ props }) => (
              <StixCyberObservableEntitiesLines
                data={props}
                paginationOptions={paginationOptions}
                displayRelation={true}
                stixCyberObservableId={entityId}
              />
            )}
          />
        </List>
      </Card>
    </div>
  );
};

StixCyberObservableEntities.propTypes = {
  entityId: PropTypes.string,
  relationship_type: PropTypes.string,
  classes: PropTypes.object,
  navigate: PropTypes.func,
  defaultStartTime: PropTypes.string,
  defaultStopTime: PropTypes.string,
};

export default withStyles(styles)(StixCyberObservableEntities);
