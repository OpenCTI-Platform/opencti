import Avatar from '@mui/material/Avatar';
import Box from '@mui/material/Box';
import { Field } from 'formik';
import React, { FunctionComponent, useCallback, useEffect, useState } from 'react';
import { graphql } from 'react-relay';
import AutocompleteField from '../../../../components/AutocompleteField';
import { useFormatter } from '../../../../components/i18n';
import { fetchQuery } from '../../../../relay/environment';
import { hexToRGB } from '../../../../utils/Colors';
import { FieldOption } from '../../../../utils/field';
import useDebounceCallback from '../../../../utils/hooks/useDebounceCallback';
import useHelper from '../../../../utils/hooks/useHelper';
import { StatusScopeEnum } from '../../../../utils/statusConstants';
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
            id
            name
            color
          }
        }
      }
    }
  }
`;

// Task 5, Step 4.5: lightweight, non-admin-gated check for whether `type` currently has a
// published WorkflowDefinition (new engine). When combined with the `ENTITIES_WORKFLOW` feature
// flag, this decides whether the legacy free-choice Status dropdown must become read-only for
// that entity type, so users can't bypass the new engine's enforced transitions via this
// pre-existing field (plan.md Task 5, "StatusField is a free-choice bypass" design gap).
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

  useEffect(() => {
    if (!type || !isWorkflowUiEnabledForType(type, isFeatureEnable)) {
      setHasPublishedWorkflowDefinition(false);
      return;
    }
    fetchQuery(statusFieldWorkflowDefinitionPublishedQuery, { entityType: type })
      .toPromise()
      .then((data) => {
        const queryData = data as StatusFieldWorkflowDefinitionPublishedQuery$data;
        setHasPublishedWorkflowDefinition(!!queryData?.workflowDefinitionPublished);
      });
  }, [type, isFeatureEnable]);

  const isWorkflowManaged = !!type && isWorkflowUiEnabledForType(type, isFeatureEnable) && hasPublishedWorkflowDefinition;


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
          ? t_i18n('This status is managed by the workflow. Use the workflow transitions to change it.')
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
