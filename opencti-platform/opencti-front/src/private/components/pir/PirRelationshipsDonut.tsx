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

import { graphql } from 'react-relay';
import { PirRelationshipsDonutDistributionQuery$data } from './__generated__/PirRelationshipsDonutDistributionQuery.graphql';
import WidgetDonut from '../../../components/dashboard/WidgetDonut';
import WidgetNoData from '../../../components/dashboard/WidgetNoData';
import Loader, { LoaderVariant } from '../../../components/Loader';
import WidgetContainer from '../../../components/dashboard/WidgetContainer';
import { QueryRenderer } from '../../../relay/environment';
import { buildFiltersAndOptionsForWidgets } from '../../../utils/filters/filtersUtils';
import type { PirWidgetDataSelection } from '../../../utils/widget/widget';

export const pirRelationshipsDonutsDistributionQuery = graphql`
  query PirRelationshipsDonutDistributionQuery(
    $pirId: ID!
    $field: String!
    $operation: StatsOperation!
    $startDate: DateTime
    $endDate: DateTime
    $dateAttribute: String
    $isTo: Boolean
    $limit: Int
    $fromId: [String]
    $fromTypes: [String]
    $relationship_type: [String]
    $search: String
    $filters: FilterGroup
    $dynamicFrom: FilterGroup
  ) {
    pirRelationshipsDistribution(
      pirId: $pirId
      field: $field
      operation: $operation
      startDate: $startDate
      endDate: $endDate
      dateAttribute: $dateAttribute
      isTo: $isTo
      limit: $limit
      fromId: $fromId
      fromTypes: $fromTypes
      relationship_type: $relationship_type
      search: $search
      filters: $filters
      dynamicFrom: $dynamicFrom
    ) {
      label
      value
      entity {
        ... on BasicObject {
          id
          entity_type
        }
        ... on BasicRelationship {
          id
          entity_type
        }
        ... on StixObject {
          representative {
            main
          }
        }
        ... on StixRelationship {
          representative {
            main
          }
        }
      }
    }
  }
`;

interface PirRelationshipsDonutProps {
  pirId: string;
}

const PirRelationshipsDonut = ({ pirId }: PirRelationshipsDonutProps) => {
  const renderContent = () => {
    const selection: PirWidgetDataSelection = {
      attribute: 'pir_explanation.dependencies.author_id',
      isTo: false,
      relationship_type: 'in-pir',
      pirId,
    };
    const filtersAndOptions = buildFiltersAndOptionsForWidgets(selection.filters); ;

    const finalField = selection?.attribute || 'entity_type';
    const variables = {
      ...selection,
      field: finalField,
      operation: 'count',
      startDate: null,
      endDate: null,
      dateAttribute: selection?.date_attribute ?? 'created_at',
      limit: selection?.number ?? 10,
      filters: filtersAndOptions?.filters,
      isTo: selection?.isTo,
      dynamicFrom: selection?.dynamicFrom,
      dynamicTo: selection?.dynamicTo,
    };

    return (
      <QueryRenderer
        query={pirRelationshipsDonutsDistributionQuery}
        variables={variables}
        render={({ props }: { props: PirRelationshipsDonutDistributionQuery$data }) => {
          if (
            props
            && props.pirRelationshipsDistribution
            && props.pirRelationshipsDistribution.length > 0
          ) {
            return (
              <WidgetDonut
                // eslint-disable-next-line @typescript-eslint/no-explicit-any
                data={props.pirRelationshipsDistribution as any[]}
                groupBy={finalField}
              />
            );
          }
          if (props) {
            return <WidgetNoData />;
          }
          return <Loader variant={LoaderVariant.inElement} />;
        }}
      />
    );
  };

  return (
    <WidgetContainer
      height={250}
      variant="inLine"
    >
      {renderContent()}
    </WidgetContainer>
  );
};

export default PirRelationshipsDonut;
