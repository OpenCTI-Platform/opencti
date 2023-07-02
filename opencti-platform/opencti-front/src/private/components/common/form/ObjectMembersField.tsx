import { graphql } from 'react-relay';
import makeStyles from '@mui/styles/makeStyles';
import React, { FunctionComponent, useState } from 'react';
import { Field } from 'formik';
import { Theme } from '../../../../components/Theme';
import { fetchQuery } from '../../../../relay/environment';
import { useFormatter } from '../../../../components/i18n';
import { ObjectMembersFieldSearchQuery$data } from './__generated__/ObjectMembersFieldSearchQuery.graphql';
import AutocompleteField from '../../../../components/AutocompleteField';
import ItemIcon from '../../../../components/ItemIcon';
import { Option } from './ReferenceField';

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
    query ObjectMembersFieldSearchQuery($search: String, $first: Int) {
        members(search: $search, first: $first) {
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

interface OptionMember extends Option {
  type: string;
}

interface ObjectMembersFieldProps {
  name: string;
  label?: string;
  multiple?: boolean;
  onChange?: (name: string, value: string | string[]) => void;
  style?: Record<string, string | number>;
  helpertext?: string;
}
const ObjectMembersField: FunctionComponent<ObjectMembersFieldProps> = ({
  name,
  label,
  multiple,
  style,
  onChange,
  helpertext,
}) => {
  const classes = useStyles();
  const { t } = useFormatter();
  const [members, setMembers] = useState<OptionMember[]>([]);
  const searchMembers = (event: React.ChangeEvent<HTMLInputElement>) => {
    fetchQuery(objectMembersFieldSearchQuery, {
      search: event && event.target.value ? event.target.value : '',
      first: 50,
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
        name={name}
        multiple={multiple ?? false}
        textfieldprops={{
          variant: 'standard',
          label: t(label ?? 'Users, groups or organizations'),
          helperText: helpertext,
          onFocus: searchMembers,
        }}
        onChange={(n: string, v: Option | Option[]) => {
          if (onChange && Array.isArray(v)) {
            onChange(n, v.map((nV) => nV?.value ?? nV));
          } else if (onChange && !Array.isArray(v)) {
            onChange(n, v?.value ?? v);
          }
        }}
        style={style}
        noOptionsText={t('No available options')}
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
