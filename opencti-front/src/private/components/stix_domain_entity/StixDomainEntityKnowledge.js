import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import {
  compose, filter, head, includes, map,
} from 'ramda';
import graphql from 'babel-plugin-relay/macro';
import Select from '@material-ui/core/Select';
import Input from '@material-ui/core/Input';
import Chip from '@material-ui/core/Chip';
import MenuItem from '@material-ui/core/MenuItem';
import { withStyles } from '@material-ui/core/styles';
import { QueryRenderer, fetchQuery, requestSubscription } from '../../../relay/environment';
import { currentYear, parse, yearFormat } from '../../../utils/Time';
import inject18n from '../../../components/i18n';
import StixDomainEntityKnowledgeGraph from './StixDomainEntityKnowledgeGraph';

const styles = theme => ({
  container: {
    width: '100%',
    height: '100%',
    margin: 0,
    padding: 0,
    position: 'relative',
  },
  filters: {
    position: 'absolute',
    top: -50,
    right: 0,
  },
  chips: {
    display: 'flex',
    flexWrap: 'wrap',
  },
  chip: {
    margin: theme.spacing.unit / 4,
  },
});

const subscription = graphql`
    subscription StixDomainEntityKnowledgeSubscription($id: ID!) {
        stixDomainEntity(id: $id) {
            ...StixDomainEntityKnowledgeGraph_stixDomainEntity
        }
    }
`;

const firstStixRelationQuery = graphql`
    query StixDomainEntityKnowledgeFirstStixRelationQuery($fromId: String, $first: Int, $orderBy: StixRelationsOrdering, $orderMode: OrderingMode) {
        stixRelations(fromId: $fromId, first: $first, orderBy: $orderBy, orderMode: $orderMode) {
            edges {
                node {
                    id
                    first_seen
                }
            }
        }
    }
`;

const stixDomainEntityKnowledgeQuery = graphql`
    query StixDomainEntityKnowledgeQuery($id: String!, $count: Int, $toTypes: [String], $firstSeenStart: DateTime, $firstSeenStop: DateTime, $lastSeenStart: DateTime, $lastSeenStop: DateTime, $weights: [Int]) {
        stixDomainEntity(id: $id) {
            ...StixDomainEntityKnowledgeGraph_stixDomainEntity @arguments(toTypes: $toTypes, firstSeenStart: $firstSeenStart, firstSeenStop: $firstSeenStop, lastSeenStart: $lastSeenStart, lastSeenStop: $lastSeenStop, weights: $weights, first: $count)
        }
    }
`;

class StixDomainEntityKnowledge extends Component {
  constructor(props) {
    super(props);
    this.state = {
      toTypes: ['All'],
      firstSeen: 'All years',
      firstSeenFirstYear: currentYear(),
      firstSeenStart: null,
      firstSeenStop: null,
      weights: [0],
    };
  }

  componentDidMount() {
    const { stixDomainEntityId } = this.props;
    fetchQuery(firstStixRelationQuery, {
      fromId: stixDomainEntityId,
      first: 1,
      orderBy: 'first_seen',
      orderMode: 'asc',
    }).then((data) => {
      if (data.stixRelations.edges.length > 0) {
        this.setState({ firstSeenFirstYear: yearFormat(head(data.stixRelations.edges).node.first_seen) });
      }
    });
  }

  isSavable() {
    const {
      firstSeenStart, firstSeenStop, weights, toTypes,
    } = this.state;
    if (firstSeenStart === null
      && firstSeenStop === null
      && includes(0, weights)
      && includes('All', toTypes)) {
      return true;
    }
  }

  handleChangeEntities(event) {
    const { value } = event.target;
    if (includes('All', this.state.toTypes) || !includes('All', value)) {
      const toTypes = filter(v => v !== 'All', value);
      if (toTypes.length > 0) {
        return this.setState({ toTypes });
      }
    }
    return this.setState({ toTypes: ['All'] });
  }

  handleChangeYear(event) {
    const { value } = event.target;
    if (value !== 'All years') {
      const startDate = `${value}-01-01`;
      const endDate = `${value}-12-31`;
      this.setState({
        firstSeen: value,
        firstSeenStart: parse(startDate).format(),
        firstSeenStop: parse(endDate).format(),
      });
    } else {
      this.setState({
        firstSeen: value,
        firstSeenStart: null,
        firstSeenStop: null,
      });
    }
  }

  handleChangeWeights(event) {
    const { value } = event.target;
    if (includes(0, this.state.weights) || !includes(0, value)) {
      const weights = filter(v => v !== 0, value);
      if (weights.length > 0) {
        this.setState({ weights });
      } else {
        this.setState({ weights: [0] });
      }
    }
  }

  render() {
    const { t, classes, stixDomainEntityId } = this.props;
    const startYear = this.state.firstSeenFirstYear === currentYear() ? this.state.firstSeenFirstYear - 1 : this.state.firstSeenFirstYear;
    const yearsList = [];
    for (let i = startYear; i <= currentYear(); i++) {
      yearsList.push(i);
    }
    const variables = {
      id: stixDomainEntityId,
      count: 100,
      toTypes: includes('All', this.state.toTypes) ? null : this.state.toTypes,
      firstSeenStart: null,
      firstSeenStop: null,
      weights: includes(0, this.state.weights) ? null : this.state.weights,
    };

    return (
      <div className={classes.container}>
        <div className={classes.filters}>
          <Select
            style={{ height: 50 }}
            multiple={true}
            value={this.state.toTypes}
            onChange={this.handleChangeEntities.bind(this)}
            input={<Input id='entities'/>}
            renderValue={selected => (
              <div className={classes.chips}>
                {selected.map(value => (
                  <Chip key={value} label={t(`entity_${value.toLowerCase()}`)} className={classes.chip}/>
                ))}
              </div>
            )}
          >
            <MenuItem value='All'>{t('All entities')}</MenuItem>
            <MenuItem value='Country'>{t('Country')}</MenuItem>
            <MenuItem value='Sector'>{t('Sector')}</MenuItem>
            <MenuItem value='Organization'>{t('Organization')}</MenuItem>
            <MenuItem value='User'>{t('Person')}</MenuItem>
            <MenuItem value='Threat-Actor'>{t('Threat actor')}</MenuItem>
            <MenuItem value='Intrusion-Set'>{t('Intrusion set')}</MenuItem>
            <MenuItem value='Campaign'>{t('Campaign')}</MenuItem>
            <MenuItem value='Incident'>{t('Incident')}</MenuItem>
            <MenuItem value='Malware'>{t('Malware')}</MenuItem>
            <MenuItem value='Tool'>{t('Tool')}</MenuItem>
            <MenuItem value='Vulnerability'>{t('Vulnerability')}</MenuItem>
            <MenuItem value='Attack-Pattern'>{t('Attack pattern')}</MenuItem>
          </Select>
          <Select
            style={{ height: 50, marginLeft: 20 }}
            multiple={true}
            value={this.state.weights}
            onChange={this.handleChangeWeights.bind(this)}
            input={<Input id='weights'/>}
            renderValue={selected => (
              <div className={classes.chips}>
                {selected.map(value => (
                  <Chip key={value} label={t(`confidence_${value}`)} className={classes.chip}/>
                ))}
              </div>
            )}
          >
            <MenuItem value={0}>{t('All confidence levels')}</MenuItem>
            <MenuItem value={1}>{t('Very low')}</MenuItem>
            <MenuItem value={2}>{t('Low')}</MenuItem>
            <MenuItem value={3}>{t('Medium')}</MenuItem>
            <MenuItem value={4}>{t('High')}</MenuItem>
            <MenuItem value={5}>{t('Very high')}</MenuItem>
          </Select>
          <Select
            style={{ width: 170, height: 50, marginLeft: 20 }}
            value={this.state.firstSeen}
            onChange={this.handleChangeYear.bind(this)}
            renderValue={selected => (
              <div className={classes.chips}>
                <Chip key={selected} label={t(selected)} className={classes.chip}/>
              </div>
            )}
          >
            <MenuItem value='All years'>{t('All years')}</MenuItem>
            {map(year => (<MenuItem key={year} value={year}>{year}</MenuItem>), yearsList)}
          </Select>
        </div>
        <QueryRenderer
          query={stixDomainEntityKnowledgeQuery}
          variables={variables}
          render={({ props }) => {
            if (props && props.stixDomainEntity) {
              return (
                <StixDomainEntityKnowledgeGraph
                  isSavable={this.isSavable.bind(this)}
                  variables={variables}
                  stixDomainEntity={props.stixDomainEntity}
                  firstSeenYear={this.state.firstSeenStart ? yearFormat(this.state.firstSeenStart) : 'all'}
                />
              );
            }
            return (
              <div> &nbsp; </div>
            );
          }}
        />
      </div>
    );
  }
}

StixDomainEntityKnowledge.propTypes = {
  stixDomainEntityId: PropTypes.string,
  classes: PropTypes.object,
  t: PropTypes.func,
};

export default compose(
  inject18n,
  withStyles(styles),
)(StixDomainEntityKnowledge);
