import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { Route, Redirect, withRouter } from 'react-router-dom';
import graphql from 'babel-plugin-relay/macro';
import { QueryRenderer, requestSubscription } from '../../../../relay/environment';
import TopBar from '../../nav/TopBar';
import Country from './Country';
import CountryReports from './CountryReports';
import CountryKnowledge from './CountryKnowledge';

const subscription = graphql`
  subscription RootCountriesSubscription($id: ID!) {
    stixDomainEntity(id: $id) {
      ... on Country {
        ...Country_country
        ...CountryEditionContainer_country
      }
    }
  }
`;

const countryQuery = graphql`
  query RootCountryQuery($id: String!) {
    country(id: $id) {
      ...Country_country
      ...CountryHeader_country
      ...CountryOverview_country
      ...CountryReports_country
      ...CountryKnowledge_country
    }
  }
`;

class RootCountry extends Component {
  componentDidMount() {
    const {
      match: {
        params: { countryId },
      },
    } = this.props;
    const sub = requestSubscription({
      subscription,
      variables: { id: countryId },
    });
    this.setState({ sub });
  }

  componentWillUnmount() {
    this.state.sub.dispose();
  }

  render() {
    const {
      me,
      match: {
        params: { countryId },
      },
    } = this.props;
    return (
      <div>
        <TopBar me={me || null} />
        <QueryRenderer
          query={countryQuery}
          variables={{ id: countryId }}
          render={({ props }) => {
            if (props && props.country) {
              return (
                <div>
                  <Route
                    exact
                    path="/dashboard/entities/countries/:countryId"
                    render={routeProps => (
                      <Country {...routeProps} country={props.country} />
                    )}
                  />
                  <Route
                    exact
                    path="/dashboard/entities/countries/:countryId/reports"
                    render={routeProps => (
                      <CountryReports {...routeProps} country={props.country} />
                    )}
                  />
                  <Route
                    exact
                    path="/dashboard/entities/countries/:countryId/knowledge"
                    render={() => (
                      <Redirect
                        to={`/dashboard/entities/countries/${countryId}/knowledge/overview`}
                      />
                    )}
                  />
                  <Route
                    path="/dashboard/entities/countries/:countryId/knowledge"
                    render={routeProps => (
                      <CountryKnowledge
                        {...routeProps}
                        country={props.country}
                      />
                    )}
                  />
                </div>
              );
            }
            return <div> &nbsp; </div>;
          }}
        />
      </div>
    );
  }
}

RootCountry.propTypes = {
  children: PropTypes.node,
  match: PropTypes.object,
  me: PropTypes.object,
};

export default withRouter(RootCountry);
