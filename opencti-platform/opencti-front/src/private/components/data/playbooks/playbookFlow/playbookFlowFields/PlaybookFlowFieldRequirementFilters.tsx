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

import { useState } from 'react';
import { Field } from 'formik';
import { graphql } from 'react-relay';
import { ComboboxChangeMeta } from '@filigran/design-system';
import { useFormatter } from '../../../../../../components/i18n';
import { fieldSpacingContainerStyle } from '../../../../../../utils/field';
import { fetchQuery } from '../../../../../../relay/environment';
import ComboboxField from '../../../../../../components/ComboboxField';
import type { FieldOption } from '../../../../../../utils/field';
import type { PlaybookFlowFieldRequirementFiltersQuery$data } from './__generated__/PlaybookFlowFieldRequirementFiltersQuery.graphql';

const requirementsQuery = graphql`
  query PlaybookFlowFieldRequirementFiltersQuery($search: String, $first: Int) {
    intelligenceRequirements(search: $search, first: $first) {
      edges {
        node {
          id
          name
        }
      }
    }
  }
`;

// The requirements an entry "Listen intelligence requirement events" listens to (none selected: every requirement)
export const toRequirementOptions = (data: PlaybookFlowFieldRequirementFiltersQuery$data | null | undefined): FieldOption[] => {
  return (data?.intelligenceRequirements?.edges ?? []).flatMap((edge) => (edge?.node ? [{ label: edge.node.name, value: edge.node.id }] : []));
};

const PlaybookFlowFieldRequirementFilters = () => {
  const { t_i18n } = useFormatter();
  const [options, setOptions] = useState<FieldOption[]>([]);

  const search = async (text: string) => {
    const data = await fetchQuery(requirementsQuery, { search: text, first: 50 }).toPromise() as PlaybookFlowFieldRequirementFiltersQuery$data;
    setOptions(toRequirementOptions(data));
  };

  return (
    <Field
      component={ComboboxField}
      style={fieldSpacingContainerStyle}
      name="requirementFilters"
      multiple
      label={t_i18n('Intelligence requirements')}
      helperText={t_i18n('If no intelligence requirement is selected, the playbook listens to every intelligence requirement')}
      noOptionsText={t_i18n('No available options')}
      options={options}
      onInputChange={(text: string, meta: ComboboxChangeMeta) => {
        if (meta.cause === 'type') search(text);
      }}
      onFocusInput={() => search('')}
    />
  );
};

export default PlaybookFlowFieldRequirementFilters;
