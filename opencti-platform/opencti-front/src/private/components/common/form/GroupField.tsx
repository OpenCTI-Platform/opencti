import React, { useState } from 'react';
import { Field } from 'formik';
import { graphql } from 'react-relay';
import { GroupFieldQuery$data } from '@components/common/form/__generated__/GroupFieldQuery.graphql';
import makeStyles from '@mui/styles/makeStyles';
import { fetchQuery } from '../../../../relay/environment';
import AutocompleteField from '../../../../components/AutocompleteField';
import { useFormatter } from '../../../../components/i18n';
import ItemIcon from '../../../../components/ItemIcon';

// Deprecated - https://mui.com/system/styles/basics/
// Do not use it for new code.
const useStyles = makeStyles({
  icon: {
    paddingTop: 4,
    display: 'inline-block',
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

export const groupsQuery = graphql`
  query GroupFieldQuery(
    $orderMode: OrderingMode
    $orderBy: GroupsOrdering
    $filters: FilterGroup
  ) {
    groups(
      orderMode: $orderMode
      orderBy: $orderBy
      filters: $filters
    ) {
      edges {
        node {
          id
          name
          group_confidence_level {
            max_confidence
          }
        }
      }
    }
  }
`;

type GroupFieldOption = {
  label: string,
  value: string,
};

interface GroupFieldProps {
  name: string,
  label: React.ReactNode,
  style?: React.CSSProperties,
  onChange?: unknown,
  multiple?: boolean,
  helpertext?: string,
  disabled?: boolean,
  predefinedGroups?: GroupFieldOption[],
  showConfidence?: boolean,
}

const GroupField: React.FC<GroupFieldProps> = (props) => {
  const { t_i18n } = useFormatter();
  const classes = useStyles();
  const {
    name,
    label,
    style,
    onChange,
    multiple = true,
    helpertext,
    disabled = false,
    predefinedGroups,
    showConfidence = false,
  } = props;

  const [groups, setGroups] = useState<GroupFieldOption[]>([]);

  const searchGroups = () => {
    if (predefinedGroups) {
      setGroups(predefinedGroups);
    } else {
      fetchQuery(groupsQuery, { orderBy: 'name', orderMode: 'asc' })
        .toPromise()
        .then((data) => {
          const dataGroups = (data as GroupFieldQuery$data).groups?.edges ?? [];
          const newGroups = dataGroups.map((n) => {
            const max_confidence = n?.node.group_confidence_level
              ? `${t_i18n('Max Confidence Level:')} ${n.node.group_confidence_level.max_confidence}`
              : t_i18n('No Max Confidence Level');
            const groupLabel = n?.node.name ?? '';
            const groupLabelInList = showConfidence
              ? `${n?.node.name} (${max_confidence})`
              : n?.node.name ?? '';
            return {
              label: groupLabel,
              labelInList: groupLabelInList,
              value: n?.node.id ?? '',
            };
          });
          setGroups(newGroups);
        });
    }
  };

  return (
    <Field
      component={AutocompleteField}
      style={style}
      name={name}
      multiple={multiple}
      disabled={disabled}
      textfieldprops={{
        variant: 'standard',
        label: label ?? t_i18n('Groups'),
        helperText: helpertext,
        onFocus: searchGroups,
      }}
      noOptionsText={t_i18n('No available options')}
      options={groups}
      onInputChange={searchGroups}
      onChange={typeof onChange === 'function' ? onChange : null}
      renderOption={(renderProps: React.HTMLAttributes<HTMLLIElement>, option: { color: string; label: string, labelInList?: string }) => (
        <li {...renderProps}>
          <div className={classes.icon} style={{ color: option.color }}>
            <ItemIcon type="Group" />
          </div>
          <div className={classes.text}>{option.labelInList ?? option.label}</div>
        </li>
      )}
      classes={{ clearIndicator: classes.autoCompleteIndicator }}
    />
  );
};

export default GroupField;
