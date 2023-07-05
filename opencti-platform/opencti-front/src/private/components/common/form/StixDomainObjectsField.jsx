import React, { Component } from 'react';
import { compose, pathOr, pipe, map, union } from 'ramda';
import { debounce } from 'rxjs/operators';
import { Subject, timer } from 'rxjs';
import { Field } from 'formik';
import withStyles from '@mui/styles/withStyles';
import { graphql } from 'react-relay';
import { fetchQuery } from '../../../../relay/environment';
import AutocompleteField from '../../../../components/AutocompleteField';
import inject18n from '../../../../components/i18n';
import { defaultValue } from '../../../../utils/Graph';
import ItemIcon from '../../../../components/ItemIcon';

const SEARCH$ = new Subject().pipe(debounce(() => timer(1500)));

export const stixDomainObjectsFieldSearchQuery = graphql`
  query StixDomainObjectsFieldSearchQuery(
    $types: [String]
    $search: String
    $first: Int
  ) {
    stixDomainObjects(types: $types, search: $search, first: $first) {
      edges {
        node {
          id
          entity_type
          parent_types
          created_at
          createdBy {
            ... on Identity {
              id
              name
              entity_type
            }
          }
          objectMarking {
            edges {
              node {
                id
                definition_type
                definition
                x_opencti_order
                x_opencti_color
              }
            }
          }
          ... on AttackPattern {
            name
            description
            x_mitre_id
          }
          ... on Campaign {
            name
            description
            first_seen
            last_seen
          }
          ... on Note {
            attribute_abstract
          }
          ... on ObservedData {
            name
            first_observed
            last_observed
          }
          ... on Opinion {
            opinion
          }
          ... on Report {
            name
            description
            published
          }
          ... on Grouping {
            name
            description
          }
          ... on CourseOfAction {
            name
            description
          }
          ... on Individual {
            name
            description
          }
          ... on Organization {
            name
            description
          }
          ... on Sector {
            name
            description
          }
          ... on System {
            name
            description
          }
          ... on Indicator {
            name
            description
            valid_from
          }
          ... on Infrastructure {
            name
            description
          }
          ... on IntrusionSet {
            name
            description
            first_seen
            last_seen
          }
          ... on Position {
            name
            description
          }
          ... on City {
            name
            description
          }
          ... on AdministrativeArea {
            name
            description
          }
          ... on Country {
            name
            description
          }
          ... on Region {
            name
            description
          }
          ... on Malware {
            name
            description
            first_seen
            last_seen
          }
          ... on ThreatActor {
            name
            description
            first_seen
            last_seen
          }
          ... on Tool {
            name
            description
          }
          ... on Vulnerability {
            name
            description
          }
          ... on Incident {
            name
            description
            first_seen
            last_seen
          }
        }
      }
    }
  }
`;

const styles = () => ({
  icon: {
    paddingTop: 4,
    display: 'inline-block',
  },
  text: {
    display: 'inline-block',
    flexGrow: 1,
    marginLeft: 10,
  },
  autoCompleteIndicator: {
    display: 'none',
  },
});

class StixDomainObjectsField extends Component {
  constructor(props) {
    super(props);
    this.state = { stixDomainObjects: [], keyword: '' };
  }

  componentDidMount() {
    this.subscription = SEARCH$.subscribe({
      next: () => this.searchStixDomainObjects(),
    });
  }

  componentWillUnmount() {
    this.subscription.unsubscribe();
  }

  handleSearch(event) {
    if (event && event.target && event.target.value) {
      this.setState({ keyword: event.target.value });
      SEARCH$.next({ action: 'Search' });
    }
  }

  searchStixDomainObjects() {
    fetchQuery(stixDomainObjectsFieldSearchQuery, {
      types: this.props.types || ['Stix-Domain-Object'],
      search: this.state.keyword,
      first: 20,
    })
      .toPromise()
      .then((data) => {
        const labels = pipe(
          pathOr([], ['stixDomainObjects', 'edges']),
          map((n) => ({
            label: defaultValue(n.node),
            value: n.node.id,
            type: n.node.entity_type,
          })),
        )(data);
        this.setState({
          stixDomainObjects: union(this.state.stixDomainObjects, labels),
        });
      });
  }

  render() {
    const { t, name, style, classes, helpertext, onChange } = this.props;
    return (
      <div>
        <Field
          component={AutocompleteField}
          style={style}
          name={name}
          multiple={true}
          textfieldprops={{
            variant: 'standard',
            label: t('Entities'),
            helperText: helpertext,
            onFocus: this.searchStixDomainObjects.bind(this),
          }}
          noOptionsText={t('No available options')}
          options={this.state.stixDomainObjects}
          onInputChange={this.handleSearch.bind(this)}
          onChange={typeof onChange === 'function' ? onChange.bind(this) : null}
          renderOption={(props, option) => (
            <li {...props}>
              <div className={classes.icon} style={{ color: option.color }}>
                <ItemIcon type={option.type} />
              </div>
              <div className={classes.text}>{option.label}</div>
            </li>
          )}
          classes={{ clearIndicator: classes.autoCompleteIndicator }}
        />
      </div>
    );
  }
}

export default compose(inject18n, withStyles(styles))(StixDomainObjectsField);
