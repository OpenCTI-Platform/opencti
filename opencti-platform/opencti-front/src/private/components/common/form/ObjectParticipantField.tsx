import React, { FunctionComponent, useState } from 'react';
import { Field } from 'formik';
import { graphql } from 'react-relay';
import { makeStyles } from '@mui/styles';
import { fetchQuery } from '../../../../relay/environment';
import AutocompleteField from '../../../../components/AutocompleteField';
import { useFormatter } from '../../../../components/i18n';
import ItemIcon from '../../../../components/ItemIcon';
import type { Theme } from '../../../../components/Theme';
import { Option } from './ReferenceField';
import { ObjectParticipantFieldMembersSearchQuery$data } from './__generated__/ObjectParticipantFieldMembersSearchQuery.graphql';

const objectParticipantFieldMembersSearchQuery = graphql`
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

// Deprecated - https://mui.com/system/styles/basics/
// Do not use it for new code.
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

interface OptionParticipant extends Option {
  type: string;
}
interface ObjectParticipantFieldProps {
  name: string;
  required?: boolean;
  onChange?: (name: string, values: OptionParticipant[]) => void;
  style?: Record<string, string | number>;
  helpertext?: string;
  label?: string,
  disabled?: boolean,
}
const ObjectParticipantField: FunctionComponent<ObjectParticipantFieldProps> = ({
  name,
  style,
  label,
  onChange,
  helpertext,
  disabled,
  required = false,
}) => {
  const classes = useStyles();
  const { t_i18n } = useFormatter();
  const [participants, setParticipants] = useState<OptionParticipant[]>([]);

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
        })).sort((a, b) => a.label.localeCompare(b.label));
        setParticipants(newParticipants);
      });
  };
  return (
    <Field
      component={AutocompleteField}
      style={style}
      name={name}
      required={required}
      disabled={disabled}
      multiple={true}
      textfieldprops={{
        variant: 'standard',
        label: label ?? t_i18n('Participant(s)'),
        required,
        helperText: helpertext,
        onFocus: searchParticipants,
      }}
      noOptionsText={t_i18n('No available options')}
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
