/*
Copyright (c) 2021-2025 Filigran SAS

This file is part of the OpenCTI Enterprise Edition ("EE") and is
licensed under the OpenCTI Enterprise Edition License (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

https://github.com/OpenCTI-Platform/opencti/blob/master/LICENSE

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
*/

import { useEffect, useState } from 'react';
import { Field, useFormikContext } from 'formik';
import { graphql } from 'react-relay';
import ComboboxField from '../../../../../../../components/ComboboxField';
import { useFormatter } from '../../../../../../../components/i18n';
import { fetchQuery } from '../../../../../../../relay/environment';
import { FieldOption } from '../../../../../../../utils/field';
import { StatusScopeEnum } from '../../../../../../../utils/statusConstants';
import StatusField from '../../../../../common/form/StatusField';
import type { PlaybookStatusValueFieldStatusTypesQuery$data } from './__generated__/PlaybookStatusValueFieldStatusTypesQuery.graphql';
import { PlaybookUpdateAction, PlaybookUpdateActionsForm } from './playbookAction-types';

const playbookStatusValueFieldStatusTypesQuery = graphql`
  query PlaybookStatusValueFieldStatusTypesQuery($first: Int, $after: ID, $filters: FilterGroup) {
    statuses(first: $first, after: $after, filters: $filters) {
      pageInfo {
        endCursor
        hasNextPage
      }
      edges {
        node {
          type
        }
      }
    }
  }
`;

// Every entity type carrying a global status, read page by page
const fetchStatusEntityTypes = async (): Promise<string[]> => {
  const types = new Set<string>();
  let after: string | null | undefined = null;
  let hasNextPage = true;
  while (hasNextPage) {
    const data = await fetchQuery(playbookStatusValueFieldStatusTypesQuery, {
      first: 500,
      after,
      filters: { mode: 'and', filterGroups: [], filters: [{ key: 'scope', values: [StatusScopeEnum.GLOBAL] }] },
    }).toPromise() as PlaybookStatusValueFieldStatusTypesQuery$data;
    (data?.statuses?.edges ?? []).forEach((edge) => types.add(edge.node.type));
    after = data?.statuses?.pageInfo.endCursor;
    hasNextPage = !!data?.statuses?.pageInfo.hasNextPage && !!after;
  }
  // A playbook bundle never carries a draft workspace
  types.delete('DraftWorkspace');
  return [...types];
};

interface PlaybookStatusValueFieldProps {
  action: PlaybookUpdateAction;
  index: number;
  disabled?: boolean;
}

// A status belongs to the workflow of one entity type, as in the table mass operation:
// the type is picked first, then only the statuses of its workflow are listed.
const PlaybookStatusValueField = ({ action, index, disabled = false }: PlaybookStatusValueFieldProps) => {
  const { t_i18n } = useFormatter();
  const { setFieldValue } = useFormikContext<PlaybookUpdateActionsForm>();
  const [entityTypes, setEntityTypes] = useState<string[]>([]);

  useEffect(() => {
    let active = true;
    fetchStatusEntityTypes()
      .then((types) => {
        if (active) setEntityTypes(types);
      })
      // The type list stays empty, the field shows no available options
      .catch(() => {
        if (active) setEntityTypes([]);
      });
    return () => {
      active = false;
    };
  }, []);

  const entityTypeOptions: FieldOption[] = entityTypes
    .map((type) => ({ label: t_i18n(`entity_${type}`), value: type }))
    .sort((a, b) => a.label.localeCompare(b.label));
  const entityType = action.entity_type;

  return (
    <div style={{ display: 'flex', gap: 16 }}>
      <div style={{ flex: 1, minWidth: 0 }}>
        <Field
          component={ComboboxField}
          name={`actions.${index}.entity_type`}
          multiple={false}
          disabled={disabled}
          required
          label={t_i18n('Entity type')}
          options={entityTypeOptions}
          noOptionsText={t_i18n('No available options')}
          getOptionLabel={(option: string | FieldOption) => (typeof option === 'string'
            ? entityTypeOptions.find((o) => o.value === option)?.label ?? option
            : option.label)}
          onInternalChange={(_: string, val: FieldOption | null) => {
            // The selected status belongs to the previous type workflow: clear only the value,
            // keep the other settings of the action (e.g. apply_transition_actions)
            const { value: _previousStatus, ...settings } = action;
            setFieldValue(`actions.${index}`, { ...settings, entity_type: val?.value });
            setFieldValue(`actionsFormValues.${index}`, null);
          }}
        />
      </div>
      <div style={{ flex: 1, minWidth: 0 }}>
        <StatusField
          // A new type starts from an empty list of statuses
          key={entityType ?? ''}
          name={`actionsFormValues.${index}`}
          type={entityType}
          workflowStatusesOnly
          disabled={disabled || !entityType}
          onChange={(_: string, status: FieldOption) => {
            setFieldValue(`actions.${index}.value`, [{ label: status.label, value: status.value, patch_value: status.value }]);
          }}
        />
      </div>
    </div>
  );
};

export default PlaybookStatusValueField;
