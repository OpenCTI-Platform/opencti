import React, { Component } from 'react';
import PropTypes from 'prop-types';
import graphql from 'babel-plugin-relay/macro';
import { Route, Redirect, withRouter } from 'react-router-dom';
import {
  compose, map, pathOr, union,
} from 'ramda';
import { Formik, Field, Form } from 'formik';
import { withStyles } from '@material-ui/core/styles';
import inject18n from '../../../components/i18n';
import { QueryRenderer, fetchQuery } from '../../../relay/environment';
import Autocomplete from '../../../components/Autocomplete';
import ExploreHeader from './ExploreHeader';
import ExploreBottomBar from './ExploreBottomBar';
import VictiomologyRightBar from './AttackPatternsRightBar';
import AttackPatternsDistribution from './AttackPatternsDistribution';
import AttackPatternsTime from './AttackPatternsTime';

const styles = () => ({
  container: {
    margin: 0,
    padding: '0 260px 100px 0',
  },
  search: {
    width: '100%',
    position: 'absolute',
    top: '40%',
    left: 0,
    padding: '0 290px 0 80px',
    textAlign: 'center',
    zIndex: 20,
  },
  input: {
    padding: '10px 20px 10px 20px',
  },
  placeholder: {
    padding: '10px 20px 10px 20px',
  },
});

const attackPatternsThreatsSearchQuery = graphql`
  query AttackPatternsThreatsSearchQuery($search: String, $first: Int) {
    threatActors(search: $search, first: $first) {
      edges {
        node {
          id
          name
          entity_type
        }
      }
    }
    intrusionSets(search: $search, first: $first) {
      edges {
        node {
          id
          name
          entity_type
        }
      }
    }
    campaigns(search: $search, first: $first) {
      edges {
        node {
          id
          name
          entity_type
        }
      }
    }
  }
`;

const attackPatternsStixDomainEntityQuery = graphql`
  query AttackPatternsStixDomainEntityQuery($id: String!) {
    stixDomainEntity(id: $id) {
      id
      ...ExploreHeader_stixDomainEntity
    }
  }
`;

class AttackPatterns extends Component {
  constructor(props) {
    super(props);
    this.state = { selectedThreat: null, threats: [], inferred: true };
  }

  searchThreats(event) {
    fetchQuery(attackPatternsThreatsSearchQuery, {
      search: event.target.value,
      first: 10,
    }).then((data) => {
      const result = pathOr([], ['threatActors', 'edges'], data)
        .concat(pathOr([], ['intrusionSets', 'edges'], data))
        .concat(pathOr([], ['campaigns', 'edges'], data));
      const threats = map(
        n => ({
          label: n.node.name,
          value: n.node.id,
          type: n.node.entity_type,
        }),
        result,
      );
      this.setState({ threats: union(this.state.threats, threats) });
    });
  }

  handleSelectThreat(name, value) {
    this.setState({ selectedThreat: value.value });
  }

  handleChangeInferred() {
    this.setState({ inferred: !this.state.inferred });
  }

  handleClear() {
    this.setState({ selectedThreat: null });
    this.props.history.push('/dashboard/explore/attack_patterns');
  }

  render() {
    const {
      classes,
      t,
      match: {
        params: { stixDomainEntityId },
      },
    } = this.props;
    const { selectedThreat } = this.state;
    const threatId = stixDomainEntityId || selectedThreat;
    return (
      <div className={classes.container}>
        {threatId === null ? (
          <div className={classes.search}>
            <Formik
              enableReinitialize={true}
              initialValues={{ searchThreat: '' }}
              render={() => (
                <Form style={{ width: 500, margin: '0 auto' }}>
                  <Field
                    classes={{
                      input: classes.input,
                      placeholder: classes.placeholder,
                    }}
                    name="searchThreat"
                    component={Autocomplete}
                    variant="outlined"
                    labelDisplay={false}
                    multiple={false}
                    label={t('Search for a threat...')}
                    options={this.state.threats}
                    onInputChange={this.searchThreats.bind(this)}
                    onChange={this.handleSelectThreat.bind(this)}
                  />
                </Form>
              )}
            />
          </div>
        ) : (
          <QueryRenderer
            query={attackPatternsStixDomainEntityQuery}
            variables={{ id: threatId }}
            render={({ props }) => {
              if (props && props.stixDomainEntity) {
                return (
                  <div>
                    <ExploreHeader stixDomainEntity={props.stixDomainEntity} />
                    <Route
                      exact
                      path="/dashboard/explore/attack_patterns"
                      render={() => (
                        <Redirect
                          to={`/dashboard/explore/attack_patterns/${threatId}/distribution`}
                        />
                      )}
                    />
                    <Route
                      exact
                      path="/dashboard/explore/attack_patterns/:stixDomainEntityId"
                      render={() => (
                        <Redirect
                          to={`/dashboard/explore/attack_patterns/${threatId}/distribution`}
                        />
                      )}
                    />
                    <Route
                      exact
                      path="/dashboard/explore/attack_patterns/:stixDomainEntityId/distribution"
                      render={routeProps => (
                        <AttackPatternsDistribution
                          {...routeProps}
                          stixDomainEntity={props.stixDomainEntity}
                          inferred={this.state.inferred}
                        />
                      )}
                    />
                    <Route
                      exact
                      path="/dashboard/explore/attack_patterns/:stixDomainEntityId/time"
                      render={routeProps => (
                        <AttackPatternsTime
                          {...routeProps}
                          stixDomainEntity={props.stixDomainEntity}
                          inferred={this.state.inferred}
                        />
                      )}
                    />
                  </div>
                );
              }
              return <div> &nbsp; </div>;
            }}
          />
        )}
        <VictiomologyRightBar threatId={threatId} />
        <ExploreBottomBar
          entityId={threatId}
          handleClear={this.handleClear.bind(this)}
          inferred={this.state.inferred}
          handleChangeInferred={this.handleChangeInferred.bind(this)}
        />
      </div>
    );
  }
}

AttackPatterns.propTypes = {
  classes: PropTypes.object,
  match: PropTypes.object,
  t: PropTypes.func,
  history: PropTypes.object,
};

export default compose(
  inject18n,
  withRouter,
  withStyles(styles),
)(AttackPatterns);
