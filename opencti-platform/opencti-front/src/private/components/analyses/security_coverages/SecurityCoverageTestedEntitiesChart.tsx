import { useFormatter } from '../../../../components/i18n';
import Card from '@common/card/Card';
import { graphql, useFragment } from 'react-relay';
import React, { FunctionComponent, useMemo } from 'react';
import Chart from '@components/common/charts/Chart';
import { ApexOptions } from 'apexcharts';
import { verticalBarsChartOptions } from '../../../../utils/Charts';
import { simpleNumberFormat } from '../../../../utils/Number';
import { useTheme } from '@mui/styles';
import type { Theme } from '../../../../components/Theme';
import { SecurityCoverageTestedEntitiesChart_securityCoverage$key } from './__generated__/SecurityCoverageTestedEntitiesChart_securityCoverage.graphql';
import WidgetNoData from '../../../../components/dashboard/WidgetNoData';

const securityCoverageRelationshipDistributionFragment = graphql`
    fragment SecurityCoverageTestedEntitiesChart_securityCoverage on SecurityCoverage{
        totalCountPerEntityType : stixCoreRelationshipsDistribution(field:"entity_type", relationship_type: "has-covered", operation:count filters: {
            mode: and
            filters: [
                { key: "toTypes", operator: not_eq, values: ["Securityplatform"] }
            ]
            filterGroups: []
        }){
            label,
            value
        }
        testedCountPerEntityType: stixCoreRelationshipsDistribution(field:"entity_type", relationship_type: "has-covered", operation:count, filters: {
            mode: and
            filters: [
                { key: "coverage_information", operator: not_nil, values: [] }
                { key: "toTypes", operator: not_eq, values: ["Securityplatform"] }
            ]
            filterGroups: []
        } ){
            label,
            value
        }
    }
`;

interface Props {
  securityCoverage: SecurityCoverageTestedEntitiesChart_securityCoverage$key;
}

function normalizeDistribution(
  arr: ReadonlyArray<
    | { readonly label: string; readonly value: number | null | undefined }
    | null
    | undefined
  > | null | undefined,
) {
  return (arr ?? [])
    .filter((v) => v != null)
    .map(({ label, value }) => ({
      label,
      value: value ?? 0,
    }));
}

const SecurityCoverageTestedEntitiesChart: FunctionComponent<Props> = ({ securityCoverage }) => {
  const { t_i18n } = useFormatter();
  const theme = useTheme<Theme>();
  const data = useFragment(securityCoverageRelationshipDistributionFragment, securityCoverage);

  const totalCounts = normalizeDistribution(data.totalCountPerEntityType);
  const testedCounts = normalizeDistribution(data.testedCountPerEntityType);

  const { categories, testedData, notCoveredData } = useMemo(() => {
    const testedByLabel = new Map(
      (testedCounts || []).map(({ label, value }) => [label, value]),
    );

    const sortedEntities = (totalCounts ?? [])
      .sort((a, b) => (a.label).localeCompare(b.label));

    const categories: string[] = [];
    const testedData: number[] = [];
    const notCoveredData: number[] = [];

    for (const { label, value } of sortedEntities) {
      const tested = testedByLabel.get(label) ?? 0;
      const total = value ?? 0;

      categories.push(t_i18n(`entity_${label}`) ?? '');
      testedData.push(tested);
      notCoveredData.push(total - tested);
    }

    return { categories, testedData, notCoveredData };
  }, [totalCounts, testedCounts]);

  const series = useMemo(() => [
    {
      name: t_i18n('Tested entities'),
      data: testedData,
    },
    {
      name: t_i18n('Not covered'),
      data: notCoveredData,
    },
  ], [testedData, notCoveredData]);

  const options: ApexOptions = useMemo(
    () => ({
      ...verticalBarsChartOptions(
        theme,
        t_i18n,
        simpleNumberFormat,
        false,
        false,
        true,
        false,
        undefined,
      ) as ApexOptions,
      xaxis: { categories },
    }),
    [theme, categories],
  );

  return (
    <Card title={t_i18n('Tested entities')}>
      {categories.length === 0
        ? <WidgetNoData /> : (
            <Chart
              options={options}
              series={series}
              type="bar"
              width="100%"
              height="100%"
            />
          )}

    </Card>
  );
};

export default SecurityCoverageTestedEntitiesChart;
