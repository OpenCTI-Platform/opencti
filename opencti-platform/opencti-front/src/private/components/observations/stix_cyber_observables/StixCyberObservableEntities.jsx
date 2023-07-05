import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { compose } from 'ramda';
import withStyles from '@mui/styles/withStyles';
import Typography from '@mui/material/Typography';
import Paper from '@mui/material/Paper';
import List from '@mui/material/List';
import ListItem from '@mui/material/ListItem';
import ListItemIcon from '@mui/material/ListItemIcon';
import ListItemText from '@mui/material/ListItemText';
import ListItemSecondaryAction from '@mui/material/ListItemSecondaryAction';
import { ArrowDropDown, ArrowDropUp } from '@mui/icons-material';
import { interval } from 'rxjs';
import { QueryRenderer } from '../../../../relay/environment';
import inject18n from '../../../../components/i18n';
import StixCyberObservableEntitiesLines, {
  stixCyberObservableEntitiesLinesQuery,
} from './StixCyberObservableEntitiesLines';
import StixCoreRelationshipCreationFromEntity from '../../common/stix_core_relationships/StixCoreRelationshipCreationFromEntity';
import Security from '../../../../utils/Security';
import { KNOWLEDGE_KNUPDATE } from '../../../../utils/hooks/useGranted';
import SearchInput from '../../../../components/SearchInput';
import { TEN_SECONDS } from '../../../../utils/Time';

const interval$ = interval(TEN_SECONDS);

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
  },
  entity_tyoe: {
    float: 'left',
    width: '10%',
    fontSize: 12,
    fontWeight: '700',
  },
  name: {
    float: 'left',
    width: '22%',
    fontSize: 12,
    fontWeight: '700',
  },
  createdBy: {
    float: 'left',
    width: '12%',
    fontSize: 12,
    fontWeight: '700',
  },
  creator: {
    float: 'left',
    width: '12%',
    fontSize: 12,
    fontWeight: '700',
  },
  start_time: {
    float: 'left',
    width: '10%',
    fontSize: 12,
    fontWeight: '700',
    cursor: 'pointer',
  },
  stop_time: {
    float: 'left',
    width: '10%',
    fontSize: 12,
    fontWeight: '700',
    cursor: 'pointer',
  },
  confidence: {
    float: 'left',
    width: '12%',
    fontSize: 12,
    fontWeight: '700',
    cursor: 'pointer',
  },
};

class StixCyberObservableEntities extends Component {
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

  componentDidMount() {
    this.subscription = interval$.subscribe(() => {
      this.props.relay.refetchConnection(25);
    });
  }

  componentWillUnmount() {
    this.subscription.unsubscribe();
  }

  handleReverseRelation() {
    this.setState({ relationReversed: !this.state.relationReversed });
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
    const { sortBy, orderAsc, searchTerm, relationReversed } = this.state;
    const { classes, t, entityId, defaultStartTime, defaultStopTime } = this.props;
    const paginationOptions = {
      elementId: entityId,
      search: searchTerm,
      orderBy: sortBy,
      orderMode: orderAsc ? 'asc' : 'desc',
    };
    return (
      <div style={{ height: '100%' }}>
        <Typography variant="h4" gutterBottom={true} style={{ float: 'left' }}>
          {t('Relations')}
        </Typography>
        <Security
          needs={[KNOWLEDGE_KNUPDATE]}
          placeholder={<div style={{ height: 29 }} />}
        >
          <StixCoreRelationshipCreationFromEntity
            paginationOptions={paginationOptions}
            handleReverseRelation={this.handleReverseRelation.bind(this)}
            entityId={entityId}
            variant="inLine"
            isRelationReversed={relationReversed}
            targetStixDomainObjectTypes={[
              'Threat-Actor',
              'Intrusion-Set',
              'Campaign',
              'Incident',
              'Malware',
              'Tool',
              'Vulnerability',
              'Individual',
              'Organization',
              'Sector',
              'Region',
              'Country',
              'City',
              'Position',
              'Attack-Pattern',
              'Narrative',
              'Channel',
            ]}
            targetStixCyberObservableTypes={['Stix-Cyber-Observable']}
            defaultStartTime={defaultStartTime}
            defaultStopTime={defaultStopTime}
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
                    {this.SortHeader('entity_tyoe', 'Entity type', false)}
                    {this.SortHeader('name', 'Name', false)}
                    {this.SortHeader('createdBy', 'Author', false)}
                    {this.SortHeader('creator', 'Creator', false)}
                    {this.SortHeader('start_time', 'First obs.', true)}
                    {this.SortHeader('stop_time', 'Last obs.', true)}
                    {this.SortHeader('confidence', 'Confidence level', true)}
                  </div>
                }
              />
              <ListItemSecondaryAction> &nbsp; </ListItemSecondaryAction>
            </ListItem>
            <QueryRenderer
              query={stixCyberObservableEntitiesLinesQuery}
              variables={{ count: 25, ...paginationOptions }}
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
        </Paper>
      </div>
    );
  }
}

StixCyberObservableEntities.propTypes = {
  entityId: PropTypes.string,
  relationship_type: PropTypes.string,
  classes: PropTypes.object,
  t: PropTypes.func,
  history: PropTypes.object,
  defaultStartTime: PropTypes.string,
  defaultStopTime: PropTypes.string,
};

export default compose(
  inject18n,
  withStyles(styles),
)(StixCyberObservableEntities);
