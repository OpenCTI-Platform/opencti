import React, { Component } from 'react';
import { compose, pathOr, pipe, map, union } from 'ramda';
import { Field } from 'formik';
import withStyles from '@mui/styles/withStyles';
import { graphql } from 'react-relay';
import { fetchQuery } from '../../../../relay/environment';
import AutocompleteField from '../../../../components/AutocompleteField';
import inject18n from '../../../../components/i18n';
import { defaultValue } from '../../../../utils/Graph';
import ItemIcon from '../../../../components/ItemIcon';

export const stixCoreObjectsFieldSearchQuery = graphql`
  query StixCoreObjectsFieldSearchQuery($search: String) {
    stixCoreObjects(search: $search) {
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
            context
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
          ... on ThreatActorGroup {
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
          ... on Case {
            name
          }
          ... on Task {
            name
          }
          ... on Channel {
            name
          }
          ... on Narrative {
            name
          }
          ... on Language {
            name
          }
          ... on DataComponent {
            name
          }
          ... on DataSource {
            name
          }
          ... on Case {
            name
          }
          ... on Task {
            name
          }
          ... on StixCyberObservable {
            observable_value
            x_opencti_description
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

class StixCoreObjectsField extends Component {
  constructor(props) {
    super(props);
    this.state = { stixCoreObjects: [] };
  }

  searchStixCoreObjects(event) {
    fetchQuery(stixCoreObjectsFieldSearchQuery, {
      search: event && event.target.value !== 0 ? event.target.value : '',
    })
      .toPromise()
      .then((data) => {
        const labels = pipe(
          pathOr([], ['stixCoreObjects', 'edges']),
          map((n) => ({
            label: defaultValue(n.node),
            value: n.node.id,
            type: n.node.entity_type,
          })),
        )(data);
        this.setState({
          stixCoreObjects: union(this.state.stixCoreObjects, labels),
        });
      });
  }

  render() {
    const { t, name, style, classes, helpertext } = this.props;
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
            onFocus: this.searchStixCoreObjects.bind(this),
          }}
          noOptionsText={t('No available options')}
          options={this.state.stixCoreObjects}
          onInputChange={this.searchStixCoreObjects.bind(this)}
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

export default compose(inject18n, withStyles(styles))(StixCoreObjectsField);
