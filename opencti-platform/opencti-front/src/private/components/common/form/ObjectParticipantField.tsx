import React, { FunctionComponent, useState } from 'react';
import { Field } from 'formik';
import { graphql } from 'react-relay';
import { makeStyles } from '@mui/styles';
import { fetchQuery } from '../../../../relay/environment';
import AutocompleteField from '../../../../components/AutocompleteField';
import { useFormatter } from '../../../../components/i18n';
import ItemIcon from '../../../../components/ItemIcon';
import { Theme } from '../../../../components/Theme';
import { Option } from './ReferenceField';
import {
  ObjectParticipantFieldMembersSearchQuery$data,
} from './__generated__/ObjectParticipantFieldMembersSearchQuery.graphql';

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

const useStyles = makeStyles<Theme>((theme) => ({
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

interface Participant extends Option {
  type: string;
}
interface ObjectParticipantFieldProps {
  name: string;
  onChange?: (name: string, values: Participant[]) => void;
  style?: Record<string, string | number>;
  helpertext?: string;
  defaultObjectParticipant?: Participant,
  label?: string,
  disabled?: boolean,
}
const ObjectParticipantField: FunctionComponent<ObjectParticipantFieldProps> = ({
  defaultObjectParticipant,
  name,
  style,
  label,
  onChange,
  helpertext,
  disabled,
}) => {
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
  const [participants, setParticipants] = useState<Participant>(defaultStateObjectParticipant);

  const searchParticipants = (event: React.ChangeEvent<HTMLInputElement>) => {
    fetchQuery(objectParticipantFieldMembersSearchQuery, {
      search: (event && event.target && event.target.value) ?? '',
      entityTypes: ['User'],
      first: 10,
    })
      .toPromise()
      .then((data) => {
        const newParticipants = (
          (data as ObjectParticipantFieldMembersSearchQuery$data)?.members?.edges ?? []
        ).map((n) => ({
          label: n.node.name,
          value: n.node.id,
          type: n.node.entity_type,
          entity: n.node,
        })).sort((a, b) => a.label.localeCompare(b.label));
        setParticipants(newParticipants);
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
        options={participants}
        onInputChange={searchParticipants}
        onChange={typeof onChange === 'function' ? onChange : null}
        renderOption={(
          fieldProps: React.HTMLAttributes<HTMLLIElement>,
          option: { type: string; label: string },
        ) => (
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

export default ObjectParticipantField;
