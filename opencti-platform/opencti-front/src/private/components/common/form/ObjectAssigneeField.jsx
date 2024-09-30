import React, { useEffect, useState } from 'react';
import { pathOr, pipe, map, union } from 'ramda';
import { debounce } from 'rxjs/operators';
import { Subject, timer } from 'rxjs';
import { Field } from 'formik';
import { graphql } from 'react-relay';
import { fetchQuery } from '../../../../relay/environment';
import AutocompleteField from '../../../../components/AutocompleteField';
import { useFormatter } from '../../../../components/i18n';
import ItemIcon from '../../../../components/ItemIcon';
import makeStyles from '@mui/styles/makeStyles';

const SEARCH$ = new Subject().pipe(debounce(() => timer(1500)));

export const objectAssigneeFieldMembersSearchQuery = graphql`
  query ObjectAssigneeFieldMembersSearchQuery($search: String, $first: Int, $entityTypes: [MemberType!]) {
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

export const objectAssigneeFieldAssigneesSearchQuery = graphql`
  query ObjectAssigneeFieldAssigneesSearchQuery($entityTypes: [String!]) {
    assignees(entityTypes: $entityTypes) {
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

const useStyles = makeStyles((theme) => ({
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
}));

const ObjectAssigneeField = (props) => {
  const { defaultObjectAssignee, name, style, label, onChange, helpertext, disabled } = props;
  const classes = useStyles();
  const { t_i18n } = useFormatter();
  const [keyword, setKeyword] = useState('');
  const [assignees, setAssignee] = useState(defaultObjectAssignee ? [
      {
        label: defaultObjectAssignee.name,
        value: defaultObjectAssignee.id,
        type: defaultObjectAssignee.entity_type,
        entity: defaultObjectAssignee,
      },
    ]
    : []);

  useEffect(() => {
    const subscription = SEARCH$.subscribe({
      next: () => searchAssignees(),
    });
    return subscription.unsubscribe();
  });

  const handleSearch = (event) => {
    if (event && event.target && event.target.value) {
      setKeyword(event.target.value);
      SEARCH$.next({ action: 'Search' });
    }
  }

  const searchAssignees = () => {
    fetchQuery(objectAssigneeFieldMembersSearchQuery, {
      search: keyword,
      entityTypes: ['User'],
      first: 10,
    })
      .toPromise()
      .then((data) => {
        const newAssignees = pipe(
          pathOr([], ['members', 'edges']),
          map((n) => ({
            label: n.node.name,
            value: n.node.id,
            type: n.node.entity_type,
            entity: n.node,
          })),
        )(data);
        setAssignee(union(assignees, newAssignees));
      });
  }

  return (
    <Field component={AutocompleteField}
           style={style}
           name={name}
           disabled={disabled}
           multiple={true}
           textfieldprops={{
             variant: 'standard',
             label: label ?? t_i18n('Assignee(s)'),
             helperText: helpertext,
             onFocus: searchAssignees,
           }}
           noOptionsText={t_i18n('No available options')}
           options={assignees.sort((a, b) => a.label.localeCompare(b.label))}
           onInputChange={handleSearch}
           onChange={typeof onChange === 'function' ? onChange : null}
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

export default ObjectAssigneeField;
