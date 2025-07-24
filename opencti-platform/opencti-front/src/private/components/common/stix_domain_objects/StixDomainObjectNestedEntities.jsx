import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { compose } from 'ramda';
import withStyles from '@mui/styles/withStyles';
import Typography from '@mui/material/Typography';
import List from '@mui/material/List';
import StixNestedRefRelationshipCreationFromEntityContainer from '../stix_nested_ref_relationships/StixNestedRefRelationshipCreationFromEntityContainer';
import inject18n from '../../../../components/i18n';
import Security from '../../../../utils/Security';
import { KNOWLEDGE_KNUPDATE } from '../../../../utils/hooks/useGranted';
import { QueryRenderer } from '../../../../relay/environment';
import StixDomainObjectNestedEntitiesLines, { stixDomainObjectNestedEntitiesLinesQuery } from './StixDomainObjectNestedEntitiesLines';

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

  render() {
    const { searchTerm, sortBy, orderAsc } = this.state;
    const { entityId, t, entityType } = this.props;
    const paginationOptions = {
      fromOrToId: entityId,
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
  }
}

StixDomainObjectNestedEntities.propTypes = {
  entityId: PropTypes.string,
  entityType: PropTypes.string,
  paginationOptions: PropTypes.object,
  classes: PropTypes.object,
  t: PropTypes.func,
  navigate: PropTypes.object,
  defaultStartTime: PropTypes.string,
  defaultStopTime: PropTypes.string,
};

export default compose(
  inject18n,
  withStyles(styles),
)(StixDomainObjectNestedEntities);
