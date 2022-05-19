import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { compose } from 'ramda';
import withStyles from '@mui/styles/withStyles';
import Typography from '@mui/material/Typography';
import { ArrowDropDown, ArrowDropUp } from '@mui/icons-material';
import List from '@mui/material/List';
import inject18n from '../../../../components/i18n';
import StixCyberObservableRelationshipCreationFromEntity from '../stix_cyber_observable_relationships/StixCyberObservableRelationshipCreationFromEntity';
import Security, { KNOWLEDGE_KNUPDATE } from '../../../../utils/Security';
import { QueryRenderer } from '../../../../relay/environment';
import StixDomainObjectNestedEntitiesLines, {
  stixDomainObjectNestedEntitiesLinesQuery,
} from './StixDomainObjectNestedEntitiesLines';

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
    width: '20%',
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
    width: '40%',
    fontSize: 12,
    fontWeight: '700',
  },
  start_time: {
    float: 'left',
    fontSize: 12,
    fontWeight: '700',
    cursor: 'pointer',
  },
};

class StixDomainObjectNestedEntities extends Component {
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
    const { entityId, t, entityType } = this.props;
    const paginationOptions = {
      elementId: entityId,
      search: searchTerm,
      orderBy: sortBy,
      orderMode: orderAsc ? 'asc' : 'desc',
    };
    return (
      <div style={{ marginTop: 20 }}>
        <Typography variant="h4" gutterBottom={true} style={{ float: 'left' }}>
          {t('Nested objects')}
        </Typography>
        <Security
          needs={[KNOWLEDGE_KNUPDATE]}
          placeholder={<div style={{ height: 29 }} />}
        >
          <StixCyberObservableRelationshipCreationFromEntity
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
  }
}

StixDomainObjectNestedEntities.propTypes = {
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
)(StixDomainObjectNestedEntities);
