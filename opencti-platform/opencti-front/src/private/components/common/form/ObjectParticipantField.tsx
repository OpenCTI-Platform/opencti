import React, { FunctionComponent, useContext, useState } from 'react';
import { Field } from 'formik';
import { graphql } from 'react-relay';
import { makeStyles } from '@mui/styles';
import { fetchQuery } from '../../../../relay/environment';
import type { ComboboxChangeMeta } from '@filigran/design-system';
import ComboboxField from '../../../../components/ComboboxField';
import { useFormatter } from '../../../../components/i18n';
import ItemIcon from '../../../../components/ItemIcon';
import type { Theme } from '../../../../components/Theme';
import { ObjectParticipantFieldMembersSearchQuery$data } from './__generated__/ObjectParticipantFieldMembersSearchQuery.graphql';
import { UserContext } from '../../../../utils/hooks/useAuth';
import { FieldOption } from '../../../../utils/field';

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
}));

interface OptionParticipant extends FieldOption {
  type: string;
  group: string;
}
interface ObjectParticipantFieldProps {
  name: string;
  required?: boolean;
  onChange?: (name: string, values: OptionParticipant[]) => void;
  style?: Record<string, string | number>;
  helpertext?: unknown;
  label?: string;
  disabled?: boolean;
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
  const { me } = useContext((UserContext));
  const [participants, setParticipants] = useState<OptionParticipant[]>([]);

  const searchParticipants = (search: string) => {
    fetchQuery(objectParticipantFieldMembersSearchQuery, {
      search,
      entityTypes: ['User'],
      first: 10,
    })
      .toPromise()
      .then((data) => {
        const newParticipants = (
          (data as ObjectParticipantFieldMembersSearchQuery$data)?.members?.edges ?? []
        ).map((n) => {
          const group = n.node.id === me?.id ? t_i18n('Current User') : t_i18n('All');
          return {
            label: n.node.name,
            value: n.node.id,
            type: n.node.entity_type,
            group,
          };
        });
        // Add current user if is not in the only first results displayed
        const isMeDisplayed = newParticipants.find((participant) => participant.value === me?.id);
        if (me && !isMeDisplayed) newParticipants.unshift({ label: me.name, value: me.id, type: 'User', group: t_i18n('Current User') });
        newParticipants.sort((a, b) => {
          // Display first the current user
          if (a.value === me?.id) return -1;
          if (b.value === me?.id) return 1;
          // Sort by alphabetic order
          return a.label.localeCompare(b.label);
        });
        setParticipants(newParticipants);
      });
  };
  return (
    <Field
      component={ComboboxField}
      // MUI hid its clear indicator here with display:none; the library defaults
      // clearable to true, so the affordance must be declined explicitly.
      style={style}
      name={name}
      required={required}
      disabled={disabled}
      multiple={true}
      groupBy={(option: OptionParticipant) => option.group}
      label={label ?? t_i18n('Participant(s)')}
      helperText={helpertext}
      noOptionsText={t_i18n('No available options')}
      options={participants}
      onInputChange={(search: string, meta: ComboboxChangeMeta) => {
        if (meta.cause === 'type') searchParticipants(search);
      }}
      onFocusInput={() => searchParticipants('')}
      onChange={typeof onChange === 'function' ? onChange : null}
      renderOption={(option: { type: string; label: string }) => (
        <>
          <div className={classes.icon}>
            <ItemIcon type={option.type} />
          </div>
          <div className={classes.text}>{option.label}</div>
        </>
      )}
    />
  );
};

export default ObjectParticipantField;
