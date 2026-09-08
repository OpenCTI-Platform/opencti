import React, { FunctionComponent, useCallback, useEffect, useState } from 'react';
import { Field } from 'formik';
import { graphql } from 'react-relay';
import Avatar from '@mui/material/Avatar';
import Box from '@mui/material/Box';
import { fetchQuery } from '../../../../relay/environment';
import AutocompleteField from '../../../../components/AutocompleteField';
import { useFormatter } from '../../../../components/i18n';
import { hexToRGB } from '../../../../utils/Colors';
import { StatusScopeEnum } from '../../../../utils/statusConstants';
import { FieldOption } from '../../../../utils/field';
import useDebounceCallback from '../../../../utils/hooks/useDebounceCallback';
import useHelper from '../../../../utils/hooks/useHelper';
import { isWorkflowUiEnabledForType } from '../workflow/workflowFeatureFlag';
import type { StatusFieldStatusesSearchQuery$data } from './__generated__/StatusFieldStatusesSearchQuery.graphql';
import type { StatusFieldWorkflowDefinitionPublishedQuery$data } from './__generated__/StatusFieldWorkflowDefinitionPublishedQuery.graphql';

interface StatusOption extends FieldOption {
  order: number;
}

interface DefaultStatus {
  id: string;
  order: number;
  type: string;
  template: {
    name: string;
    color: string;
  };
}

interface StatusFieldProps {
  name: string;
  type?: string;
  scope?: string;
  style?: React.CSSProperties;
  onChange?: (name: string, value: FieldOption) => void;
  onFocus?: (name: string, id: string) => void;
  setFieldValue?: (field: string, value: unknown) => void;
  helpertext?: React.ReactNode;
  defaultStatus?: DefaultStatus;
  required?: boolean;
  disabled?: boolean;
}

export const statusFieldStatusesSearchQuery = graphql`
  query StatusFieldStatusesSearchQuery(
    $first: Int
    $orderBy: StatusOrdering
    $orderMode: OrderingMode
    $filters: FilterGroup
    $search: String
  ) {
    statuses(
      first: $first
      orderBy: $orderBy
      orderMode: $orderMode
      filters: $filters
      search: $search
    ) {
      edges {
        node {
          id
          order
          type
          template {
            name
            color
          }
        }
      }
    }
  }
`;

export const statusFieldWorkflowDefinitionPublishedQuery = graphql`
  query StatusFieldWorkflowDefinitionPublishedQuery($entityType: String!) {
    workflowDefinitionPublished(entityType: $entityType)
  }
`;

const StatusField: FunctionComponent<StatusFieldProps> = ({
  name,
  type,
  scope,
  style,
  onChange,
  helpertext,
  defaultStatus,
  required = false,
  disabled = false,
}) => {
  const { t_i18n } = useFormatter();
  const { isFeatureEnable } = useHelper();
  const [keyword, setKeyword] = useState<string>('');
  const [hasPublishedWorkflowDefinition, setHasPublishedWorkflowDefinition] = useState<boolean>(false);
  const [statuses, setStatuses] = useState<StatusOption[]>(
    defaultStatus
      ? [{
          label: defaultStatus.template.name,
          color: defaultStatus.template.color,
          value: defaultStatus.id,
          order: defaultStatus.order,
          type: defaultStatus.type,
        }]
      : [],
  );

  const searchStatuses = useCallback((searchKeyword: string = '') => {
    fetchQuery(statusFieldStatusesSearchQuery, {
      first: 100,
      filters: type
        ? {
            mode: 'and',
            filterGroups: [],
            filters: [
              { key: 'type', values: [type] },
              { key: 'scope', values: [scope || StatusScopeEnum.GLOBAL] },
            ],
          }
        : null,
      orderBy: 'order',
      orderMode: 'asc',
      search: searchKeyword,
    })
      .toPromise()
      .then((data) => {
        const queryData = data as StatusFieldStatusesSearchQuery$data;
        const edges = queryData?.statuses?.edges ?? [];
        const newStatuses: StatusOption[] = edges
          .filter((edge) => edge?.node?.template != null)
          .map((edge) => ({
            label: edge.node.template!.name,
            value: edge.node.id,
            order: edge.node.order,
            color: edge.node.template!.color,
            type: edge.node.type,
          }));
        newStatuses.sort((a, b) => ((a.type ?? '') < (b.type ?? '') ? -1 : 1));
        setStatuses((prev) => {
          const combined = [...prev, ...newStatuses];
          const unique = combined.filter((item, index) => combined.findIndex((e) => e.value === item.value) === index);
          return unique;
        });
      });
  }, [type, scope]);

  const debouncedSearchStatuses = useDebounceCallback(searchStatuses, 1500);

  const isWorkflowUiEnabled = !!type && isWorkflowUiEnabledForType(type, isFeatureEnable);

  useEffect(() => {
    if (!type || !isWorkflowUiEnabled) {
      setHasPublishedWorkflowDefinition(false);
      return;
    }
    fetchQuery(statusFieldWorkflowDefinitionPublishedQuery, { entityType: type })
      .toPromise()
      .then((data) => {
        const queryData = data as StatusFieldWorkflowDefinitionPublishedQuery$data;
        setHasPublishedWorkflowDefinition(!!queryData?.workflowDefinitionPublished);
      });
  }, [type, isWorkflowUiEnabled]);

  const isWorkflowManaged = hasPublishedWorkflowDefinition;

  const handleSearch = useCallback((_event: React.SyntheticEvent, value: string) => {
    if (value) {
      setKeyword(value);
      debouncedSearchStatuses(value);
    }
  }, [debouncedSearchStatuses]);

  const handleFocus = useCallback(() => {
    searchStatuses(keyword);
  }, [searchStatuses, keyword]);

  return (
    <Field
      component={AutocompleteField}
      style={style}
      name={name}
      required={required}
      disabled={disabled || isWorkflowManaged}
      textfieldprops={{
        variant: 'standard',
        label: t_i18n('Status'),
        helperText: isWorkflowManaged
          ? t_i18n('This entity type is managed by a workflow, status is read-only here')
          : helpertext,
        onFocus: handleFocus,
      }}
      noOptionsText={t_i18n('No available options')}
      options={statuses}
      onInputChange={handleSearch}
      groupBy={type ? undefined : (option: StatusOption) => option.type}
      onChange={typeof onChange === 'function' ? onChange : null}
      renderOption={(props: React.HTMLAttributes<HTMLLIElement>, option: StatusOption) => (
        <li {...props} key={option.value}>
          <Box sx={{ pt: '4px', display: 'inline-block', color: 'primary.main' }}>
            <Avatar
              variant="square"
              style={{
                color: option.color,
                borderColor: option.color,
                backgroundColor: hexToRGB(option.color),
              }}
            >
              {option.order}
            </Avatar>
          </Box>
          <Box sx={{ display: 'inline-block', flexGrow: 1, ml: '10px' }}>{option.label}</Box>
        </li>
      )}
      sx={{ '& .MuiAutocomplete-clearIndicator': { display: 'none' } }}
    />
  );
};

export default StatusField;
