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
import ItemIcon from '../../../../components/ItemIcon';

const SEARCH$ = new Subject().pipe(debounce(() => timer(1500)));

export const objectParticipantFieldMembersSearchQuery = graphql`
  query ObjectParticipantFieldMembersSearchQuery($search: String, $first: Int, $entityTypes: [MemberType!]) {
    members(search: $search, first: $first, entityTypes: $entityTypes) {
      edges {
        node {
          id
          entity_type
          name
        }
      }
    }
  }
`;

export const objectParticipantFieldParticipantsSearchQuery = graphql`
  query ObjectParticipantFieldParticipantsSearchQuery($entityTypes: [String!]) {
    participants(entityTypes: $entityTypes) {
      edges {
        node {
          id
          entity_type
          name
        }
      }
    }
  }
`;

const styles = (theme) => ({
  icon: {
    paddingTop: 4,
    display: 'inline-block',
    color: theme.palette.primary.main,
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

class ObjectParticipantField extends Component {
  constructor(props) {
    super(props);
    const { defaultObjectParticipant } = props;
    this.state = {
      keyword: '',
      participants: defaultObjectParticipant
        ? [
          {
            label: defaultObjectParticipant.name,
            value: defaultObjectParticipant.id,
            type: defaultObjectParticipant.entity_type,
            entity: defaultObjectParticipant,
          },
        ]
        : [],
    };
  }

  componentDidMount() {
    this.subscription = SEARCH$.subscribe({
      next: () => this.searchParticipants(),
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

  searchParticipants() {
    fetchQuery(objectParticipantFieldMembersSearchQuery, {
      search: this.state.keyword,
      entityTypes: ['User'],
      first: 10,
    })
      .toPromise()
      .then((data) => {
        const participants = pipe(
          pathOr([], ['members', 'edges']),
          map((n) => ({
            label: n.node.name,
            value: n.node.id,
            type: n.node.entity_type,
            entity: n.node,
          })),
        )(data);
        this.setState({ participants: union(this.state.participants, participants) });
      });
  }

  render() {
    const { t, name, style, label, classes, onChange, helpertext, disabled } = this.props;
    return (
      <Field component={AutocompleteField}
             style={style}
             name={name}
             disabled={disabled}
             multiple={true}
             textfieldprops={{
               variant: 'standard',
               label: label ?? t('Participant(s)'),
               helperText: helpertext,
               onFocus: this.searchParticipants.bind(this),
             }}
             noOptionsText={t('No available options')}
             options={this.state.participants.sort((a, b) => a.label.localeCompare(b.label))}
             onInputChange={this.handleSearch.bind(this)}
             onChange={typeof onChange === 'function' ? onChange.bind(this) : null}
             renderOption={(props, option) => (
               <li {...props}>
                 <div className={classes.icon}>
                   <ItemIcon type={option.type} />
                 </div>
                 <div className={classes.text}>{option.label}</div>
               </li>
             )}
             classes={{ clearIndicator: classes.autoCompleteIndicator }}
      />
    );
  }
}

export default compose(inject18n, withStyles(styles))(ObjectParticipantField);
