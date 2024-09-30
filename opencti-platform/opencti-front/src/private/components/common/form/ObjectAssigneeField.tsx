import React, { FunctionComponent, useContext, useEffect, useState } from 'react';
import { Field } from 'formik';
import { graphql } from 'react-relay';
import makeStyles from '@mui/styles/makeStyles';
import { fetchQuery } from '../../../../relay/environment';
import AutocompleteField from '../../../../components/AutocompleteField';
import { useFormatter } from '../../../../components/i18n';
import ItemIcon from '../../../../components/ItemIcon';
import type { Theme } from '../../../../components/Theme';
import { UserContext } from '../../../../utils/hooks/useAuth';
import { Option } from '@components/common/form/ReferenceField';
import { ObjectAssigneeFieldMembersSearchQuery$data } from '@components/common/form/__generated__/ObjectAssigneeFieldMembersSearchQuery.graphql';

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

interface OptionAssignee extends Option {
  type: string;
}
interface ObjectAssigneeFieldProps {
  name: string;
  onChange?: (name: string, values: OptionAssignee[]) => void;
  style?: Record<string, string | number>;
  helpertext?: string;
  label?: string,
  disabled?: boolean,
}
const ObjectAssigneeField: FunctionComponent<ObjectAssigneeFieldProps> = ({
  name,
  style,
  label,
  onChange,
  helpertext,
  disabled
}) => {
  const classes = useStyles();
  const { t_i18n } = useFormatter();
  const { me } = useContext((UserContext));
  const [assignees, setAssignees] = useState<OptionAssignee[]>([]);

  const searchAssignees = (event: React.ChangeEvent<HTMLInputElement>) => {
    fetchQuery(objectAssigneeFieldMembersSearchQuery, {
      search: (event && event.target && event.target.value) ?? '',
      entityTypes: ['User'],
      first: 10,
    })
      .toPromise()
      .then((data) => {
        const newAssignees = (
          (data as ObjectAssigneeFieldMembersSearchQuery$data)?.members?.edges ?? []
        ).map((n) => ({
          label: n.node.name,
          value: n.node.id,
          type: n.node.entity_type,
        })).sort((a, b) => (
          // Sort by alphabetic order
          // And display first the current user
          a.value === me?.id ? -1 : b.value === me?.id ? 1 : a.label.localeCompare(b.label))
        );
        setAssignees(newAssignees);
      });
  };

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
      options={assignees}
      onInputChange={searchAssignees}
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

export default ObjectAssigneeField;
