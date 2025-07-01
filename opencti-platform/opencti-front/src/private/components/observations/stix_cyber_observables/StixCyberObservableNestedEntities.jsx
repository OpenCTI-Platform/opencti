import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { compose } from 'ramda';
import Typography from '@mui/material/Typography';
import Paper from '@mui/material/Paper';
import { ArrowDropDown, ArrowDropUp } from '@mui/icons-material';
import List from '@mui/material/List';
import ListItem from '@mui/material/ListItem';
import ListItemIcon from '@mui/material/ListItemIcon';
import ListItemText from '@mui/material/ListItemText';
import inject18n from '../../../../components/i18n';
import StixNestedRefRelationCreationFromEntity from '../../common/stix_nested_ref_relationships/StixNestedRefRelationshipCreationFromEntity';
import Security from '../../../../utils/Security';
import { KNOWLEDGE_KNUPDATE } from '../../../../utils/hooks/useGranted';
import SearchInput from '../../../../components/SearchInput';
import { QueryRenderer } from '../../../../relay/environment';
import StixCyberObservableNestedEntitiesLines, { stixCyberObservableNestedEntitiesLinesQuery } from './StixCyberObservableNestedEntitiesLines';

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

  getTargetStixCoreObjectTypes() {
    const { entityType } = this.props;

    if (entityType === 'Network-Traffic') {
      return [
        'IPv4-Addr',
        'IPv6-Addr',
        'Domain-Name',
        'Mac-Addr',
      ];
    }
    return undefined;
  }

  render() {
    const { searchTerm, sortBy, orderAsc } = this.state;
    const { entityId, t, entityType, variant } = this.props;
    const paginationOptions = {
      fromOrToId: entityId,
      search: searchTerm,
      orderBy: sortBy,
      orderMode: orderAsc ? 'asc' : 'desc',
    };
    const isInLine = variant === 'inLine';
    const targetStixCoreObjectTypes = this.getTargetStixCoreObjectTypes();

    return (
      <div
        style={isInLine ? {
          height: 'auto',
          marginTop: 20,
          paddingBlock: 10,
        } : {
          height: '100%',
          marginTop: 0,
          paddingBlock: 0,
        }}
      >
        <Typography variant={isInLine ? 'h3' : 'h4'} gutterBottom={true} style={{ float: 'left' }}>
          {t('Nested objects')}
        </Typography>
        <Security
          needs={[KNOWLEDGE_KNUPDATE]}
          placeholder={<div style={{ height: 29 }} />}
        >
          <StixNestedRefRelationCreationFromEntity
            paginationOptions={paginationOptions}
            entityId={entityId}
            variant="inLine"
            entityType={entityType}
            targetStixCoreObjectTypes={targetStixCoreObjectTypes}
          />
        </Security>
        {!isInLine && (
          <>
            <div style={{ float: 'right', marginTop: -10 }}>
              <SearchInput
                variant="thin"
                onSubmit={this.handleSearch.bind(this)}
                keyword={searchTerm}
              />
            </div>
            <div className="clearfix"/>
          </>
        )}
        <Paper
          style={{
            margin: 0,
            padding: isInLine ? 0 : 15,
            borderRadius: 4,
          }}
          variant={isInLine ? 'default' : 'outlined'}
        >
          <List style={{ marginTop: isInLine ? 0 : -10 }}>
            <ListItem
              style={{
                paddingLeft: 10,
                paddingTop: 0,
                textTransform: 'uppercase',
              }}
              divider={false}
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
                primary={
                  <div>
                    {this.SortHeader('relationship_type', 'Attribute', true)}
                    {this.SortHeader('entity_type', 'Entity type', false)}
                    {this.SortHeader('name', 'Name', false)}
                    {this.SortHeader('creator', 'Creator', false)}
                    {this.SortHeader('start_time', 'First obs.', true)}
                    {this.SortHeader('stop_time', 'Last obs.', true)}
                  </div>
                }
              />
            </ListItem>
            <QueryRenderer
              query={stixCyberObservableNestedEntitiesLinesQuery}
              variables={{ count: 200, ...paginationOptions }}
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
  t: PropTypes.func,
  navigate: PropTypes.func,
};

export default compose(
  inject18n,
)(StixCyberObservableNestedEntities);
