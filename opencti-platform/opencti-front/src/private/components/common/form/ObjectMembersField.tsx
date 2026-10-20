import { graphql } from 'react-relay';
import makeStyles from '@mui/styles/makeStyles';
import React, { FunctionComponent, useRef, useState } from 'react';
import { Field } from 'formik';
import type { Theme } from '../../../../components/Theme';
import { fetchQuery } from '../../../../relay/environment';
import { useFormatter } from '../../../../components/i18n';
import { ObjectMembersFieldSearchQuery$data } from './__generated__/ObjectMembersFieldSearchQuery.graphql';
import type { ComboboxChangeMeta } from '@filigran/design-system';
import ComboboxField from '../../../../components/ComboboxField';
import ItemIcon from '../../../../components/ItemIcon';
import { FieldOption } from '../../../../utils/field';

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

export interface OptionMember extends FieldOption {
  type: string;
}

type MemberType = 'Group' | 'Organization' | 'User';

interface ObjectMembersFieldProps {
  name: string;
  label?: string;
  multiple?: boolean;
  onChange?: (name: string, value: FieldOption[]) => void;
  style?: Record<string, string | number>;
  helpertext?: string;
  disabled?: boolean;
  required?: boolean;
  entityTypes?: MemberType[];
  withDynamicKeys?: boolean;
  dynamicContextTypeLabel?: string;
  dynamicBundleTypeLabel?: string;
  dynamicAuthorOrgLabel?: string;
  includeBundleOrganizationDynamicOption?: boolean;
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
  withDynamicKeys,
  dynamicContextTypeLabel = 'Dynamic from context',
  dynamicBundleTypeLabel = 'Dynamic from bundle',
  dynamicAuthorOrgLabel = 'Author (organization)',
  includeBundleOrganizationDynamicOption = true,
}) => {
  const classes = useStyles();
  const { t_i18n } = useFormatter();
  const dynamicMembers: OptionMember[] = withDynamicKeys ? [
    {
      type: t_i18n(dynamicContextTypeLabel),
      value: 'AUTHOR',
      label: t_i18n(dynamicAuthorOrgLabel),
    },
    {
      type: t_i18n(dynamicContextTypeLabel),
      value: 'CREATORS',
      label: t_i18n('Creators'),
    },
    {
      type: t_i18n(dynamicContextTypeLabel),
      value: 'ASSIGNEES',
      label: t_i18n('Assignees'),
    },
    {
      type: t_i18n(dynamicContextTypeLabel),
      value: 'PARTICIPANTS',
      label: t_i18n('Participants'),
    },
    ...(includeBundleOrganizationDynamicOption
      ? [{
          type: t_i18n(dynamicBundleTypeLabel),
          value: 'BUNDLE_ORGANIZATIONS',
          label: t_i18n('Organizations'),
        }]
      : []),
  ] : [];
  const [members, setMembers] = useState<OptionMember[]>(dynamicMembers);
  // Only the latest search may update the options, older responses can resolve out of order
  const lastSearchId = useRef(0);
  const searchMembers = (search: string) => {
    lastSearchId.current += 1;
    const searchId = lastSearchId.current;
    fetchQuery(objectMembersFieldSearchQuery, {
      search,
      first: 50,
      entityTypes,
    })
      .toPromise()
      .then((data) => {
        if (searchId !== lastSearchId.current) return;
        const NewMembers = (
          (data as ObjectMembersFieldSearchQuery$data)?.members?.edges ?? []
        ).map((n) => ({
          label: n?.node.name,
          value: n?.node.id,
          type: n?.node.entity_type,
        })).sort((a, b) => (b.type ? -b.type.localeCompare(a.type) : 0));
        const templateValues = [...dynamicMembers, ...NewMembers];
        // Keep only the unique list of options
        const uniqTemplates = templateValues.filter((item, index) => {
          return (
            templateValues.findIndex((e) => e.value === item.value) === index
          );
        });
        setMembers(uniqTemplates);
      });
  };
  // Backend results are already filtered by the search, only the static dynamic options need client filtering
  const filterOptions = (options: OptionMember[], inputValue: string) => {
    const needle = inputValue.trim().toLowerCase();
    if (!needle) return options;
    const dynamicValues = new Set(dynamicMembers.map((m) => m.value));
    return options.filter((o) => !dynamicValues.has(o.value) || o.label.toLowerCase().includes(needle));
  };
  return (
    <div style={{ width: '100%' }}>
      <Field
        component={ComboboxField}
        // MUI hid its clear indicator here with display:none; the library defaults
        // clearable to true, so the affordance must be declined explicitly.
        disabled={disabled}
        name={name}
        multiple={multiple ?? false}
        label={t_i18n(label ?? 'Users, groups or organizations')}
        helperText={helpertext}
        required={required}
        onChange={(n: string, v: FieldOption[]) => onChange?.(n, v)}
        style={style}
        noOptionsText={t_i18n('No available options')}
        options={members}
        filterOptions={filterOptions}
        groupBy={(option: OptionMember) => option.type}
        onInputChange={(search: string, meta: ComboboxChangeMeta) => {
          if (meta.cause === 'type') searchMembers(search);
        }}
        onFocusInput={() => searchMembers('')}
        renderOption={(option: OptionMember) => (
          <>
            <div className={classes.icon}>
              <ItemIcon type={option.type} />
            </div>
            <div className={classes.text}>{option.label}</div>
          </>
        )}
      />
    </div>
  );
};

export default ObjectMembersField;
