import React from 'react';
import { graphql } from 'react-relay';
import { QueryRenderer } from '../../../../relay/environment';
import { useFormatter } from '../../../../components/i18n';
import { dayAgo } from '../../../../utils/Time';
import { buildFiltersAndOptionsForWidgets } from '../../../../utils/filters/filtersUtils';
import WidgetLoader from '../../../../components/dashboard/WidgetLoader';
import WidgetNoData from '../../../../components/dashboard/WidgetNoData';
import WidgetNumber from '../../../../components/dashboard/WidgetNumber';
import WidgetContainer from '../../../../components/dashboard/WidgetContainer';

const stixCoreObjectsNumberNumberQuery = graphql`
  query StixCoreObjectsNumberNumberSeriesQuery(
    $dateAttribute: String
    $types: [String]
    $startDate: DateTime
    $endDate: DateTime
    $onlyInferred: Boolean
    $filters: FilterGroup
    $search: String
  ) {
    stixCoreObjectsNumber(
      dateAttribute: $dateAttribute
      types: $types
      startDate: $startDate
      endDate: $endDate
      onlyInferred: $onlyInferred
      filters: $filters
      search: $search
    ) {
      total
      count
    }
  }
`;

const StixCoreObjectsNumber = ({
  variant,
  height,
  startDate,
  endDate,
  dataSelection,
  parameters = {},
  withoutTitle,
}) => {
  const { t_i18n } = useFormatter();
  const renderContent = () => {
    const selection = dataSelection[0];
    const dataSelectionTypes = ['Stix-Core-Object'];
    const dateAttribute = selection.date_attribute && selection.date_attribute.length > 0
      ? selection.date_attribute
      : 'created_at';
    const { filters } = buildFiltersAndOptionsForWidgets(selection.filters, { startDate, endDate, dateAttribute });
    return (
      <QueryRenderer
        query={stixCoreObjectsNumberNumberQuery}
        variables={{
          types: dataSelectionTypes,
          dateAttribute,
          filters,
          startDate,
          endDate: dayAgo(),
        }}
        render={({ props }) => {
          if (props && props.stixCoreObjectsNumber) {
            const { total, count } = props.stixCoreObjectsNumber;
            return <WidgetNumber total={total} value={count} />;
          }
          if (props) {
            return <WidgetNoData />;
          }
          return <WidgetLoader />;
        }}
      />
    );
  };
  return (
    <WidgetContainer
      height={height}
      title={parameters.title ?? t_i18n('Entities number')}
      variant={variant}
      withoutTitle={withoutTitle}
    >
      {renderContent()}
    </WidgetContainer>
  );
};

export default StixCoreObjectsNumber;
