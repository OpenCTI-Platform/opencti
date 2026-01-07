import React, { useState, FunctionComponent, useCallback } from 'react';
import * as R from 'ramda';
import { Field, useFormikContext } from 'formik';
import { graphql } from 'react-relay';
import InputAdornment from '@mui/material/InputAdornment';
import { Add, PaletteOutlined } from '@mui/icons-material';
import Popover from '@mui/material/Popover';
import MenuList from '@mui/material/MenuList';
import MenuItem from '@mui/material/MenuItem';
import Checkbox from '@mui/material/Checkbox';
import ListItemText from '@mui/material/ListItemText';
import makeStyles from '@mui/styles/makeStyles';
import IconButton from '@mui/material/IconButton';
import ItemIcon from '../../../../components/ItemIcon';
import { getMainRepresentative } from '../../../../utils/defaultRepresentatives';
import { useFormatter } from '../../../../components/i18n';
import AutocompleteField from '../../../../components/AutocompleteField';
import { fetchQuery } from '../../../../relay/environment';
import useAttributes from '../../../../utils/hooks/useAttributes';
import { displayEntityTypeForTranslation } from '../../../../utils/String';
import StixDomainObjectCreation from '../stix_domain_objects/StixDomainObjectCreation';
import StixCyberObservableCreation from '../../observations/stix_cyber_observables/StixCyberObservableCreation';
import type { Theme } from '../../../../components/Theme';
import { FieldOption } from '../../../../utils/field';

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
const useStyles = makeStyles<Theme>(() => ({
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
  createOption: {
    fontStyle: 'italic',
  },
}));

const CREATE_OPTION_VALUE = '__create_new_entity__';

interface StixCoreObjectOption {
  label: string;
  value: string;
  type: string;
  isCreateOption?: boolean;
}

interface StixCoreObjectsFieldProps {
  name: string;
  style?: React.CSSProperties;
  helpertext?: string;
  required?: boolean;
  multiple?: boolean;
  label?: string;
  disabled?: boolean;
  types?: string[] | null;
  disableCreation?: boolean;
}

interface CreatedEntity {
  id: string;
  name?: string;
  observable_value?: string;
  entity_type: string;
  representative?: {
    main?: string;
  };
}

const StixCoreObjectsField: FunctionComponent<StixCoreObjectsFieldProps> = ({
  name,
  style,
  helpertext,
  required = false,
  multiple = true,
  label,
  disabled = false,
  types = null,
  disableCreation = false,
}) => {
  const classes = useStyles();
  const { t_i18n } = useFormatter();
  const { stixCoreObjectTypes: entityTypes, stixCyberObservableTypes, stixDomainObjectTypes } = useAttributes();
  const { setFieldValue, values } = useFormikContext<Record<string, unknown>>();

  const [anchorElSearchScope, setAnchorElSearchScope] = useState<HTMLElement | null>(null);
  const [stixCoreObjects, setStixCoreObjects] = useState<StixCoreObjectOption[]>([]);
  const [searchScope, setSearchScope] = useState<Record<string, string[]>>({});
  const [currentSearchTerm, setCurrentSearchTerm] = useState('');

  // Creation dialog states
  const [openSDOCreation, setOpenSDOCreation] = useState(false);
  const [openSCOCreation, setOpenSCOCreation] = useState(false);
  const [createEntityType, setCreateEntityType] = useState<string | null>(null);
  const [valueBeforeCreate, setValueBeforeCreate] = useState<StixCoreObjectOption | StixCoreObjectOption[] | null>(null);
  // Ref to track if entity was successfully created (prevents handleClose from restoring old value)
  const entityCreatedSuccessfully = React.useRef(false);

  const handleOpenSearchScope = (event: React.MouseEvent<HTMLElement>) => setAnchorElSearchScope(event.currentTarget);
  const handleCloseSearchScope = () => setAnchorElSearchScope(null);

  const handleToggleSearchScope = (key: string, value: string) => {
    setSearchScope((c) => ({
      ...c,
      [key]: (c[key] || []).includes(value)
        ? c[key].filter((n) => n !== value)
        : [...(c[key] || []), value],
    }));
  };

  const isObservableType = useCallback((type: string) => {
    return stixCyberObservableTypes.includes(type);
  }, [stixCyberObservableTypes]);

  const isDomainObjectType = useCallback((type: string) => {
    return stixDomainObjectTypes.includes(type);
  }, [stixDomainObjectTypes]);

  const getTargetTypes = useCallback(() => {
    return types ?? searchScope[name] ?? [];
  }, [types, searchScope, name]);

  const shouldShowCreateOption = useCallback((resultsCount: number) => {
    if (disabled || disableCreation) return false;
    if (resultsCount >= 10) return false;
    const targetTypes = getTargetTypes();
    if (targetTypes.length === 0) return true;
    return targetTypes.some((t) => isDomainObjectType(t) || isObservableType(t));
  }, [disabled, disableCreation, getTargetTypes, isDomainObjectType, isObservableType]);

  const getCreationType = useCallback(() => {
    const targetTypes = getTargetTypes();
    if (targetTypes.length === 1) {
      return targetTypes[0];
    }
    return null;
  }, [getTargetTypes]);

  const handleOpenCreation = useCallback(() => {
    entityCreatedSuccessfully.current = false;
    const targetTypes = getTargetTypes();

    if (targetTypes.length === 1) {
      const singleType = targetTypes[0];
      if (isObservableType(singleType)) {
        setCreateEntityType(singleType);
        setOpenSCOCreation(true);
      } else if (isDomainObjectType(singleType)) {
        setCreateEntityType(singleType);
        setOpenSDOCreation(true);
      }
    } else if (targetTypes.length > 1) {
      const allObservables = targetTypes.every((t) => isObservableType(t));
      const allDomainObjects = targetTypes.every((t) => isDomainObjectType(t));

      if (allObservables) {
        setCreateEntityType(null);
        setOpenSCOCreation(true);
      } else if (allDomainObjects) {
        setCreateEntityType(null);
        setOpenSDOCreation(true);
      } else {
        setCreateEntityType(null);
        setOpenSDOCreation(true);
      }
    } else {
      setCreateEntityType(null);
      setOpenSDOCreation(true);
    }
  }, [getTargetTypes, isObservableType, isDomainObjectType]);

  const handleSDOEntityCreated = useCallback((createdEntity: CreatedEntity | undefined) => {
    entityCreatedSuccessfully.current = true;
    setOpenSDOCreation(false);
    setCreateEntityType(null);
    setValueBeforeCreate(null);

    if (createdEntity?.id && createdEntity?.entity_type) {
      const entityLabel = createdEntity.representative?.main
        || createdEntity.name
        || createdEntity.observable_value
        || createdEntity.id;
      const newOption: StixCoreObjectOption = {
        label: entityLabel,
        value: createdEntity.id,
        type: createdEntity.entity_type,
      };

      setStixCoreObjects((prev) => [newOption, ...prev.filter((o) => !o.isCreateOption)]);

      const currentValue = values[name] as StixCoreObjectOption | StixCoreObjectOption[] | null;
      if (multiple) {
        const currentArray = Array.isArray(currentValue) ? currentValue : [];
        setFieldValue(name, [...currentArray, newOption]);
      } else {
        setFieldValue(name, newOption);
      }
    } else {
      fetchQuery(stixCoreObjectsFieldSearchQuery, {
        search: currentSearchTerm,
        types: types ?? searchScope[name] ?? [],
      })
        .toPromise()
        .then((data: unknown) => {
          const typedData = data as { stixCoreObjects?: { edges?: Array<{ node: Record<string, unknown> }> } };
          const results = R.pipe(
            R.pathOr([], ['stixCoreObjects', 'edges']),
            R.map((n: { node: Record<string, unknown> }) => ({
              label: getMainRepresentative(n.node),
              value: n.node.id as string,
              type: n.node.entity_type as string,
            })),
          )(typedData) as StixCoreObjectOption[];

          const finalResults = [...results];
          if (shouldShowCreateOption(results.length)) {
            const creationType = getCreationType();
            const createLabel = creationType
              ? `${t_i18n('Create')} ${t_i18n(`entity_${creationType}`)}`
              : t_i18n('Create');

            finalResults.push({
              label: createLabel,
              value: CREATE_OPTION_VALUE,
              type: 'create',
              isCreateOption: true,
            });
          }

          setStixCoreObjects(finalResults);
        });
    }
  }, [currentSearchTerm, getCreationType, multiple, name, searchScope, setFieldValue, shouldShowCreateOption, t_i18n, types, values]);

  const handleSCOEntityCreated = useCallback((createdObservable?: CreatedEntity | null) => {
    entityCreatedSuccessfully.current = true;
    setOpenSCOCreation(false);
    setCreateEntityType(null);
    setValueBeforeCreate(null);

    if (createdObservable?.id && createdObservable?.entity_type) {
      const entityLabel = createdObservable.representative?.main
        || createdObservable.observable_value
        || createdObservable.name
        || createdObservable.id;
      const newOption: StixCoreObjectOption = {
        label: entityLabel,
        value: createdObservable.id,
        type: createdObservable.entity_type,
      };

      setStixCoreObjects((prev) => [newOption, ...prev.filter((o) => !o.isCreateOption)]);

      const currentValue = values[name] as StixCoreObjectOption | StixCoreObjectOption[] | null;
      if (multiple) {
        const currentArray = Array.isArray(currentValue) ? currentValue : [];
        setFieldValue(name, [...currentArray, newOption]);
      } else {
        setFieldValue(name, newOption);
      }
    } else {
      fetchQuery(stixCoreObjectsFieldSearchQuery, {
        search: currentSearchTerm,
        types: types ?? searchScope[name] ?? [],
      })
        .toPromise()
        .then((data: unknown) => {
          const typedData = data as { stixCoreObjects?: { edges?: Array<{ node: Record<string, unknown> }> } };
          const results = R.pipe(
            R.pathOr([], ['stixCoreObjects', 'edges']),
            R.map((n: { node: Record<string, unknown> }) => ({
              label: getMainRepresentative(n.node),
              value: n.node.id as string,
              type: n.node.entity_type as string,
            })),
          )(typedData) as StixCoreObjectOption[];

          const finalResults = [...results];
          if (shouldShowCreateOption(results.length)) {
            const creationType = getCreationType();
            const createLabel = creationType
              ? `${t_i18n('Create')} ${t_i18n(`entity_${creationType}`)}`
              : t_i18n('Create');

            finalResults.push({
              label: createLabel,
              value: CREATE_OPTION_VALUE,
              type: 'create',
              isCreateOption: true,
            });
          }

          setStixCoreObjects(finalResults);
        });
    }
  }, [currentSearchTerm, getCreationType, multiple, name, searchScope, setFieldValue, shouldShowCreateOption, t_i18n, types, values]);

  const searchStixCoreObjects = useCallback((event: React.SyntheticEvent | null, newInputValue?: string, reason?: string) => {
    const searchValue = newInputValue ?? '';

    if (reason === 'input' || reason === undefined) {
      setCurrentSearchTerm(searchValue);
    }

    fetchQuery(stixCoreObjectsFieldSearchQuery, {
      search: searchValue,
      types: types ?? searchScope[name] ?? [],
    })
      .toPromise()
      .then((data: unknown) => {
        const typedData = data as { stixCoreObjects?: { edges?: Array<{ node: Record<string, unknown> }> } };
        const results = R.pipe(
          R.pathOr([], ['stixCoreObjects', 'edges']),
          R.map((n: { node: Record<string, unknown> }) => ({
            label: getMainRepresentative(n.node),
            value: n.node.id as string,
            type: n.node.entity_type as string,
          })),
        )(typedData) as StixCoreObjectOption[];

        const finalResults = [...results];
        if (shouldShowCreateOption(results.length)) {
          const creationType = getCreationType();
          const createLabel = creationType
            ? `${t_i18n('Create')} ${t_i18n(`entity_${creationType}`)}`
            : t_i18n('Create');

          finalResults.push({
            label: createLabel,
            value: CREATE_OPTION_VALUE,
            type: 'create',
            isCreateOption: true,
          });
        }

        setStixCoreObjects(finalResults);
      });
  }, [getCreationType, name, searchScope, shouldShowCreateOption, t_i18n, types]);

  const entitiesTypes = R.pipe(
    R.map((n: string) => ({
      label: t_i18n(displayEntityTypeForTranslation(n)),
      value: n,
      type: n,
    })),
    R.sortWith([R.ascend(R.prop('label'))]),
    R.filter((type: { value: string }) => (types ? types.includes(type.value) : true)),
  )(entityTypes);

  const handleChange = useCallback((
    fieldName: string,
    value: StixCoreObjectOption | StixCoreObjectOption[] | null,
  ) => {
    if (!value) {
      setFieldValue(fieldName, value);
      return;
    }

    if (Array.isArray(value)) {
      const createOptionSelected = value.find((v) => v.value === CREATE_OPTION_VALUE);
      if (createOptionSelected) {
        const filteredValue = value.filter((v) => v.value !== CREATE_OPTION_VALUE);
        setValueBeforeCreate(filteredValue);
        setFieldValue(fieldName, filteredValue);
        handleOpenCreation();
        return;
      }
    } else if (value.value === CREATE_OPTION_VALUE) {
      const currentValue = values[fieldName] as StixCoreObjectOption | StixCoreObjectOption[] | null;
      setValueBeforeCreate(currentValue);
      handleOpenCreation();
      return;
    }

    setFieldValue(fieldName, value);
  }, [handleOpenCreation, setFieldValue, values]);

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
            {!disableCreation && (
              <IconButton onClick={handleOpenCreation} size="small" edge="end" disabled={disabled} title={t_i18n('Create')}>
                <Add fontSize="small" color="primary" />
              </IconButton>
            )}
            <IconButton onClick={handleOpenSearchScope} size="small" edge="end" disabled={disabled}>
              <PaletteOutlined
                fontSize="small"
                color={searchScope[name] && searchScope[name].length > 0 ? 'secondary' : 'primary'}
              />
            </IconButton>
            <Popover
              open={Boolean(anchorElSearchScope)}
              anchorEl={anchorElSearchScope}
              onClose={handleCloseSearchScope}
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
        groupBy={(option: StixCoreObjectOption) => option.isCreateOption ? '' : option.type}
        noOptionsText={t_i18n('No available options')}
        options={stixCoreObjects}
        onInputChange={searchStixCoreObjects}
        onChange={handleChange}
        filterOptions={(options: StixCoreObjectOption[]) => options}
        renderOption={(innerProps: React.HTMLAttributes<HTMLLIElement>, option: StixCoreObjectOption) => {
          if (option.isCreateOption) {
            return (
              <li {...innerProps} key={option.value}>
                <div className={classes.icon}>
                  <ItemIcon type="Add" />
                </div>
                <div className={`${classes.text} ${classes.createOption}`}>
                  {option.label}
                </div>
              </li>
            );
          }
          return (
            <li {...innerProps} key={option.value}>
              <div className={classes.icon}>
                <ItemIcon type={option.type} />
              </div>
              <div className={classes.text}>{option.label}</div>
            </li>
          );
        }}
        isOptionEqualToValue={(option: StixCoreObjectOption, value: FieldOption) => option.value === value.value}
        classes={{ clearIndicator: classes.autoCompleteIndicator }}
      />

      <StixDomainObjectCreation
        display={true}
        open={openSDOCreation}
        handleClose={() => {
          if (entityCreatedSuccessfully.current) {
            setOpenSDOCreation(false);
            setCreateEntityType(null);
            setValueBeforeCreate(null);
            return;
          }
          setOpenSDOCreation(false);
          setCreateEntityType(null);
          if (valueBeforeCreate !== null) {
            setFieldValue(name, valueBeforeCreate);
          }
          setValueBeforeCreate(null);
        }}
        speeddial={true}
        stixDomainObjectTypes={createEntityType ? [createEntityType] : (types ?? undefined)}
        inputValue={currentSearchTerm}
        creationCallback={handleSDOEntityCreated}
        confidence={undefined}
        defaultCreatedBy={undefined}
        defaultMarkingDefinitions={undefined}
        paginationKey={undefined}
        paginationOptions={undefined}
        onCompleted={undefined}
        isFromBulkRelation={false}
      />

      {openSCOCreation && (
        <StixCyberObservableCreation
          display={true}
          open={openSCOCreation}
          handleClose={() => {
            if (entityCreatedSuccessfully.current) {
              setOpenSCOCreation(false);
              setCreateEntityType(null);
              setValueBeforeCreate(null);
              return;
            }
            setOpenSCOCreation(false);
            setCreateEntityType(null);
            if (valueBeforeCreate !== null) {
              setFieldValue(name, valueBeforeCreate);
            }
            setValueBeforeCreate(null);
          }}
          contextual={true}
          speeddial={true}
          type={createEntityType ?? undefined}
          inputValue={currentSearchTerm}
          // eslint-disable-next-line @typescript-eslint/ban-ts-comment
          // @ts-ignore JSX component without proper TypeScript types
          stixCyberObservableTypes={types || undefined}
          onCompleted={handleSCOEntityCreated}
        />
      )}
    </>
  );
};

export default StixCoreObjectsField;
