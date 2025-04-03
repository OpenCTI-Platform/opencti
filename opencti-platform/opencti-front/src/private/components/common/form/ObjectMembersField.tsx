import { graphql } from 'react-relay';
import makeStyles from '@mui/styles/makeStyles';
import React, { FunctionComponent, useState } from 'react';
import { Field } from 'formik';
import type { Theme } from '../../../../components/Theme';
import { fetchQuery } from '../../../../relay/environment';
import { useFormatter } from '../../../../components/i18n';
import { ObjectMembersFieldSearchQuery$data } from './__generated__/ObjectMembersFieldSearchQuery.graphql';
import AutocompleteField from '../../../../components/AutocompleteField';
import ItemIcon from '../../../../components/ItemIcon';
import { Option } from './ReferenceField';

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

const objectMembersFieldSearchQuery = graphql`
    query ObjectMembersFieldSearchQuery($search: String, $first: Int, $entityTypes: [MemberType!]) {
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

export interface OptionMember extends Option {
  type: string;
}

type MemberType = 'Group' | 'Organization' | 'User';

interface ObjectMembersFieldProps {
  name: string;
  label?: string;
  multiple?: boolean;
  onChange?: (name: string, value: Option[]) => void;
  style?: Record<string, string | number>;
  helpertext?: string;
  disabled?: boolean;
  required?: boolean;
  entityTypes?: MemberType[];
}
const ObjectMembersField: FunctionComponent<ObjectMembersFieldProps> = ({
  name,
  label,
  multiple,
  style,
  onChange,
  helpertext,
  disabled = false,
  required = false,
  entityTypes,
}) => {
  const classes = useStyles();
  const { t_i18n } = useFormatter();
  const [members, setMembers] = useState<OptionMember[]>([]);
  const searchMembers = (event: React.ChangeEvent<HTMLInputElement>) => {
    fetchQuery(objectMembersFieldSearchQuery, {
      search: event && event.target.value ? event.target.value : '',
      first: 50,
      entityTypes,
    })
      .toPromise()
      .then((data) => {
        const NewMembers = (
          (data as ObjectMembersFieldSearchQuery$data)?.members?.edges ?? []
        ).map((n) => ({
          label: n?.node.name,
          value: n?.node.id,
          type: n?.node.entity_type,
        })).sort((a, b) => (b.type ? -b.type.localeCompare(a.type) : 0));
        const templateValues = [...members, ...NewMembers];
        // Keep only the unique list of options
        const uniqTemplates = templateValues.filter((item, index) => {
          return (
            templateValues.findIndex((e) => e.value === item.value) === index
          );
        });
        setMembers(uniqTemplates);
      });
  };
  return (
    <div style={{ width: '100%' }}>
      <Field
        component={AutocompleteField}
        disabled={disabled}
        name={name}
        multiple={multiple ?? false}
        textfieldprops={{
          variant: 'standard',
          label: t_i18n(label ?? 'Users, groups or organizations'),
          helperText: helpertext,
          onFocus: searchMembers,
        }}
        required={required}
        onChange={(n: string, v: Option[]) => onChange?.(n, v)}
        style={style}
        noOptionsText={t_i18n('No available options')}
        options={members}
        groupBy={(option: OptionMember) => option.type}
        onInputChange={searchMembers}
        renderOption={(
          props: React.HTMLAttributes<HTMLLIElement>,
          option: OptionMember,
        ) => (
          <li {...props}>
            <div className={classes.icon} >
              <ItemIcon type={option.type} />
            </div>
            <div className={classes.text}>{option.label}</div>
          </li>
        )}
        classes={{ clearIndicator: classes.autoCompleteIndicator }}
      />
    </div>
  );
};

export default ObjectMembersField;
