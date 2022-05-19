import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { compose } from 'ramda';
import withStyles from '@mui/styles/withStyles';
import Typography from '@mui/material/Typography';
import Paper from '@mui/material/Paper';
import { ArrowDropDown, ArrowDropUp } from '@mui/icons-material';
import List from '@mui/material/List';
import ListItem from '@mui/material/ListItem';
import ListItemIcon from '@mui/material/ListItemIcon';
import ListItemText from '@mui/material/ListItemText';
import ListItemSecondaryAction from '@mui/material/ListItemSecondaryAction';
import inject18n from '../../../../components/i18n';
import StixCyberObservableRelationCreationFromEntity from '../../common/stix_cyber_observable_relationships/StixCyberObservableRelationshipCreationFromEntity';
import Security, { KNOWLEDGE_KNUPDATE } from '../../../../utils/Security';
import SearchInput from '../../../../components/SearchInput';
import { QueryRenderer } from '../../../../relay/environment';
import StixCyberObservableNestedEntitiesLines, {
  stixCyberObservableNestedEntitiesLinesQuery,
} from './StixCyberObservableNestedEntitiesLines';

const styles = (theme) => ({
  paper: {
    height: '100%',
    minHeight: '100%',
    margin: 0,
    padding: 15,
    borderRadius: 6,
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
    height: 20,
    fontSize: 13,
    float: 'left',
    whiteSpace: 'nowrap',
    overflow: 'hidden',
    textOverflow: 'ellipsis',
    paddingRight: 5,
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
    width: '15%',
    fontSize: 12,
    fontWeight: '700',
    cursor: 'pointer',
  },
  entity_type: {
    float: 'left',
    width: '20%',
    fontSize: 12,
    fontWeight: '700',
  },
  name: {
    float: 'left',
    width: '35%',
    fontSize: 12,
    fontWeight: '700',
  },
  start_time: {
    float: 'left',
    width: '15%',
    fontSize: 12,
    fontWeight: '700',
    cursor: 'pointer',
  },
  stop_time: {
    float: 'left',
    width: '15%',
    fontSize: 12,
    fontWeight: '700',
    cursor: 'pointer',
  },
};

class StixCyberObservableNestedEntities extends Component {
  constructor(props) {
    super(props);
    this.state = {
      sortBy: null,
      orderAsc: false,
      searchTerm: '',
      view: 'lines',
      relationReversed: false,
    };
  }

  handleSort(field, orderAsc) {
    this.setState({ sortBy: field, orderAsc });
  }

  handleSearch(value) {
    this.setState({ searchTerm: value });
  }

  SortHeader(field, label, isSortable) {
    const { t } = this.props;
    const sortComponent = this.state.orderAsc ? (
      <ArrowDropDown style={inlineStylesHeaders.iconSort} />
    ) : (
      <ArrowDropUp style={inlineStylesHeaders.iconSort} />
    );
    if (isSortable) {
      return (
        <div
          style={inlineStylesHeaders[field]}
          onClick={this.handleSort.bind(this, field, !this.state.orderAsc)}
        >
          <span>{t(label)}</span>
          {this.state.sortBy === field ? sortComponent : ''}
        </div>
      );
    }
    return (
      <div style={inlineStylesHeaders[field]}>
        <span>{t(label)}</span>
      </div>
    );
  }

  render() {
    const { searchTerm, sortBy, orderAsc } = this.state;
    const { entityId, t, entityType, classes } = this.props;
    const paginationOptions = {
      elementId: entityId,
      search: searchTerm,
      orderBy: sortBy,
      orderMode: orderAsc ? 'asc' : 'desc',
    };
    return (
      <div style={{ height: '100%' }}>
        <Typography variant="h4" gutterBottom={true} style={{ float: 'left' }}>
          {t('Nested objects')}
        </Typography>
        <Security
          needs={[KNOWLEDGE_KNUPDATE]}
          placeholder={<div style={{ height: 29 }} />}
        >
          <StixCyberObservableRelationCreationFromEntity
            paginationOptions={paginationOptions}
            entityId={entityId}
            variant="inLine"
            entityType={entityType}
          />
        </Security>
        <div style={{ float: 'right', marginTop: -10 }}>
          <SearchInput
            variant="thin"
            onSubmit={this.handleSearch.bind(this)}
            keyword={searchTerm}
          />
        </div>
        <div className="clearfix" />
        <Paper classes={{ root: classes.paper }} variant="outlined">
          <List style={{ marginTop: -10 }}>
            <ListItem
              classes={{ root: classes.itemHead }}
              divider={false}
              style={{ paddingTop: 0 }}
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
                    {this.SortHeader('relationship_type', 'Relationship', true)}
                    {this.SortHeader('entity_type', 'Entity type', false)}
                    {this.SortHeader('name', 'Name', false)}
                    {this.SortHeader('start_time', 'First obs.', true)}
                    {this.SortHeader('stop_time', 'Last obs.', true)}
                  </div>
                }
              />
              <ListItemSecondaryAction> &nbsp; </ListItemSecondaryAction>
            </ListItem>
            <QueryRenderer
              query={stixCyberObservableNestedEntitiesLinesQuery}
              variables={{ count: 25, ...paginationOptions }}
              render={({ props }) => (
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
  }
}

StixCyberObservableNestedEntities.propTypes = {
  entityId: PropTypes.string,
  entityType: PropTypes.string,
  paginationOptions: PropTypes.object,
  classes: PropTypes.object,
  t: PropTypes.func,
  history: PropTypes.object,
};

export default compose(
  inject18n,
  withStyles(styles),
)(StixCyberObservableNestedEntities);
