import React, { useState } from 'react';
import { pathOr, pipe, map, union } from 'ramda';
import { Field } from 'formik';
import { graphql } from 'react-relay';
import * as PropTypes from 'prop-types';
import { makeStyles } from '@mui/styles';
import { fetchQuery } from '../../../../relay/environment';
import AutocompleteField from '../../../../components/AutocompleteField';
import { useFormatter } from '../../../../components/i18n';
import ItemIcon from '../../../../components/ItemIcon';

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

const ObjectParticipantField = (props) => {
  const { defaultObjectParticipant, name, style, label, onChange, helpertext, disabled } = props;
  const classes = useStyles();
  const { t } = useFormatter();
  const defaultStateObjectParticipant = defaultObjectParticipant
    ? [
      {
        label: defaultObjectParticipant.name,
        value: defaultObjectParticipant.id,
        type: defaultObjectParticipant.entity_type,
        entity: defaultObjectParticipant,
      },
    ]
    : [];
  const [participants, setParticipants] = useState(defaultStateObjectParticipant);

  const searchParticipants = (event) => {
    fetchQuery(objectParticipantFieldMembersSearchQuery, {
      search: (event && event.target && event.target.value) ?? '',
      entityTypes: ['User'],
      first: 10,
    })
      .toPromise()
      .then((data) => {
        const newParticipants = pipe(
          pathOr([], ['members', 'edges']),
          map((n) => ({
            label: n.node.name,
            value: n.node.id,
            type: n.node.entity_type,
            entity: n.node,
          })),
        )(data);
        setParticipants(union(newParticipants, participants));
      });
  };

  return (
      <Field
        component={AutocompleteField}
        style={style}
        name={name}
        disabled={disabled}
        multiple={true}
        textfieldprops={{
          variant: 'standard',
          label: label ?? t('Participant(s)'),
          helperText: helpertext,
          onFocus: searchParticipants,
        }}
        noOptionsText={t('No available options')}
        options={participants.sort((a, b) => a.label.localeCompare(b.label))}
        onInputChange={searchParticipants}
        onChange={typeof onChange === 'function' ? onChange : null}
        renderOption={(fieldProps, option) => (
           <li {...fieldProps}>
             <div className={classes.icon}>
               <ItemIcon type={option.type} />
             </div>
             <div className={classes.text}>{option.label}</div>
           </li>
        )}
        classes={{ clearIndicator: classes.autoCompleteIndicator }}
      />
  );
};

ObjectParticipantField.propTypes = {
  classes: PropTypes.object,
  t: PropTypes.func,
  defaultObjectParticipant: PropTypes.object,
  name: PropTypes.string,
  style: PropTypes.object,
  label: PropTypes.string,
  onChange: PropTypes.func,
  helpertext: PropTypes.object,
  disabled: PropTypes.bool,
};

export default ObjectParticipantField;
