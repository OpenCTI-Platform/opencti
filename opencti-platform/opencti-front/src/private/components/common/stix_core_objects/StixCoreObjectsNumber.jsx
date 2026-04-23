import { graphql } from 'react-relay';
import { QueryRenderer } from '../../../../relay/environment';
import { useFormatter } from '../../../../components/i18n';
import { dayAgo } from '../../../../utils/Time';
import { buildFiltersAndOptionsForWidgets } from '../../../../utils/filters/filtersUtils';
import WidgetNoData from '../../../../components/dashboard/WidgetNoData';
import WidgetContainer from '../../../../components/dashboard/WidgetContainer';
import Loader, { LoaderVariant } from '../../../../components/Loader';
import useEntityTranslation from '../../../../utils/hooks/useEntityTranslation';
import WidgetNumber from '../../../../components/dashboard/WidgetNumber';

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
  startDate,
  endDate,
  dataSelection,
  parameters = {},
  entityType,
  popover,
  variant,
  height,
}) => {
  const { t_i18n } = useFormatter();
  const { translateEntityType } = useEntityTranslation();

  const title = parameters.title ?? t_i18n('Entities number');
  const translatedTitle = translateEntityType(title);

  const selection = dataSelection[0];
  const dataSelectionTypes = ['Stix-Core-Object'];
  const dateAttribute = selection.date_attribute && selection.date_attribute.length > 0
    ? selection.date_attribute
    : 'created_at';
  const { filters } = buildFiltersAndOptionsForWidgets(
    selection.filters,
    { startDate, endDate, dateAttribute },
  );

  return (
    <WidgetContainer
      padding="medium"
      height={height}
      title={t_i18n('Entities number')}
      variant={variant}
      action={popover}
    >
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
            return (
              <WidgetNumber
                entityType={entityType}
                label={translatedTitle}
                value={total}
                diffLabel={t_i18n('24 hours')}
                diffValue={total - count}
              />
            );
          }
          if (props) {
            return <WidgetNoData />;
          }
          return <Loader variant={LoaderVariant.inElement} />;
        }}
      />
    </WidgetContainer>
  );
};

export default StixCoreObjectsNumber;
