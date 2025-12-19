import React, { useState } from 'react';
import * as R from 'ramda';
import { Field } from 'formik';
import { graphql } from 'react-relay';
import InputAdornment from '@mui/material/InputAdornment';
import { PaletteOutlined } from '@mui/icons-material';
import Popover from '@mui/material/Popover';
import MenuList from '@mui/material/MenuList';
import MenuItem from '@mui/material/MenuItem';
import Checkbox from '@mui/material/Checkbox';
import ListItemText from '@mui/material/ListItemText';
import makeStyles from '@mui/styles/makeStyles';
import IconButton from '@common/button/IconButton';
import ItemIcon from '../../../../components/ItemIcon';
import { getMainRepresentative } from '../../../../utils/defaultRepresentatives';
import { useFormatter } from '../../../../components/i18n';
import AutocompleteField from '../../../../components/AutocompleteField';
import { fetchQuery } from '../../../../relay/environment';
import useAttributes from '../../../../utils/hooks/useAttributes';
import { displayEntityTypeForTranslation } from '../../../../utils/String';

export const stixCoreObjectsFieldSearchQuery = graphql`
  query StixCoreObjectsFieldSearchQuery($search: String, $types: [String]) {
    stixCoreObjects(search: $search, types: $types, first: 100) {
      edges {
        node {
          id
          entity_type
          parent_types
          created_at
          createdBy {
            ... on Identity {
              id
              name
              entity_type
            }
          }
          objectMarking {
            id
            definition_type
            definition
            x_opencti_order
            x_opencti_color
          }
          ... on AttackPattern {
            name
            description
            x_mitre_id
          }
          ... on Campaign {
            name
            description
            first_seen
            last_seen
          }
          ... on Note {
            attribute_abstract
          }
          ... on ObservedData {
            name
            first_observed
            last_observed
          }
          ... on Opinion {
            opinion
          }
          ... on Report {
            name
            description
            published
          }
          ... on Grouping {
            name
            description
            context
          }
          ... on CourseOfAction {
            name
            description
          }
          ... on Individual {
            name
            description
          }
          ... on Organization {
            name
            description
          }
          ... on Event {
            name
            description
          }
          ... on Sector {
            name
            description
          }
          ... on System {
            name
            description
          }
          ... on Indicator {
            name
            description
            valid_from
          }
          ... on Infrastructure {
            name
            description
          }
          ... on IntrusionSet {
            name
            description
            first_seen
            last_seen
          }
          ... on Position {
            name
            description
          }
          ... on City {
            name
            description
          }
          ... on AdministrativeArea {
            name
            description
          }
          ... on Country {
            name
            description
          }
          ... on Region {
            name
            description
          }
          ... on Malware {
            name
            description
            first_seen
            last_seen
          }
          ... on ThreatActor {
            name
            description
            first_seen
            last_seen
          }
          ... on Tool {
            name
            description
          }
          ... on Vulnerability {
            name
            description
          }
          ... on Incident {
            name
            description
            first_seen
            last_seen
          }
          ... on Case {
            name
          }
          ... on Task {
            name
          }
          ... on Channel {
            name
          }
          ... on Narrative {
            name
          }
          ... on Language {
            name
          }
          ... on DataComponent {
            name
          }
          ... on DataSource {
            name
          }
          ... on Case {
            name
          }
          ... on Task {
            name
          }
          ... on StixCyberObservable {
            observable_value
            x_opencti_description
          }
        }
      }
    }
  }
`;

// Deprecated - https://mui.com/system/styles/basics/
// Do not use it for new code.
const useStyles = makeStyles(() => ({
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
}));

const StixCoreObjectsField = (props) => {
  const {
    name,
    style,
    helpertext,
    required = false,
    multiple = true,
    label,
    disabled = false,
    types = null,
  } = props;
  const classes = useStyles();
  const { t_i18n } = useFormatter();
  const { stixCoreObjectTypes: entityTypes } = useAttributes();
  const [anchorElSearchScope, setAnchorElSearchScope] = useState(false);
  const [stixCoreObjects, setStixCoreObjects] = useState([]);
  const [searchScope, setSearchScope] = useState({});
  const handleOpenSearchScope = (event) => setAnchorElSearchScope(event.currentTarget);
  const handleCloseSearchScope = () => setAnchorElSearchScope(undefined);
  const handleToggleSearchScope = (key, value) => {
    setSearchScope((c) => ({
      ...c,
      [key]: (searchScope[key] || []).includes(value)
        ? searchScope[key].filter((n) => n !== value)
        : [...(searchScope[key] || []), value],
    }));
  };
  const searchStixCoreObjects = (event) => {
    fetchQuery(stixCoreObjectsFieldSearchQuery, {
      search: event && event.target.value !== 0 ? event.target.value : '',
      types: types ?? searchScope[name] ?? [],
    })
      .toPromise()
      .then((data) => {
        const finalStixCoreObjects = R.pipe(
          R.pathOr([], ['stixCoreObjects', 'edges']),
          R.map((n) => ({
            label: getMainRepresentative(n.node),
            value: n.node.id,
            type: n.node.entity_type,
          })),
        )(data);
        setStixCoreObjects(finalStixCoreObjects);
      });
  };
  const entitiesTypes = R.pipe(
    R.map((n) => ({
      label: t_i18n(displayEntityTypeForTranslation(n)),
      value: n,
      type: n,
    })),
    R.sortWith([R.ascend(R.prop('label'))]),
    R.filter((type) => (types ? types.includes(type.value) : true)),
  )(entityTypes);
  return (
    <>
      <Field
        component={AutocompleteField}
        disabled={disabled}
        style={style}
        name={name}
        required={required}
        multiple={multiple}
        textfieldprops={{
          variant: 'standard',
          label: label ?? (multiple ? t_i18n('Entities') : t_i18n('Entity')),
          helperText: helpertext,
          onFocus: searchStixCoreObjects,
        }}
        endAdornment={(
          <InputAdornment position="end" style={{ position: 'absolute', right: 0 }}>
            <IconButton onClick={handleOpenSearchScope} size="small" edge="end" disabled={disabled}>
              <PaletteOutlined
                fontSize="small"
                color={searchScope[name] && searchScope[name].length > 0 ? 'secondary' : 'primary'}
              />
            </IconButton>
            <Popover
              classes={{ paper: classes.container2 }}
              open={Boolean(anchorElSearchScope)}
              anchorEl={anchorElSearchScope}
              onClose={() => handleCloseSearchScope()}
              anchorOrigin={{
                vertical: 'center',
                horizontal: 'right',
              }}
              transformOrigin={{
                vertical: 'center',
                horizontal: 'left',
              }}
              elevation={8}
            >
              <MenuList dense={true}>
                {entitiesTypes.map((entityType) => (
                  <MenuItem
                    key={entityType.value}
                    value={entityType.value}
                    dense={true}
                    onClick={() => handleToggleSearchScope(name, entityType.value)}
                  >
                    <Checkbox
                      size="small"
                      checked={(searchScope[name] || []).includes(entityType.value)}
                    />
                    <ListItemText primary={entityType.label} />
                  </MenuItem>
                ))}
              </MenuList>
            </Popover>
          </InputAdornment>
        )}
        groupBy={(option) => option.type}
        noOptionsText={t_i18n('No available options')}
        options={stixCoreObjects}
        onInputChange={searchStixCoreObjects}
        renderOption={(innerProps, option) => (
          <li {...innerProps} key={option.id}>
            <div className={classes.icon} style={{ color: option.color }}>
              <ItemIcon type={option.type} />
            </div>
            <div className={classes.text}>{option.label}</div>
          </li>
        )}
        classes={{ clearIndicator: classes.autoCompleteIndicator }}
      />
    </>
  );
};

export default StixCoreObjectsField;
