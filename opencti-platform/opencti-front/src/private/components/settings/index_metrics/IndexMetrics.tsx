import React, { Suspense } from 'react';
import Breadcrumbs from '../../../../components/Breadcrumbs';
import { useFormatter } from '../../../../components/i18n';
import Loader, { LoaderVariant } from '../../../../components/Loader';
import useConnectedDocumentModifier from '../../../../utils/hooks/useConnectedDocumentModifier';
import IndexMetricsSummary from './IndexMetricsSummary';
import IndexMetricsTable from './IndexMetricsTable';

const IndexMetricsComponent = () => {
  const { t_i18n } = useFormatter();

  return (
    <div data-testid="index-metrics-page" style={{ height: '100%' }}>
      <Breadcrumbs elements={[
        { label: t_i18n('Settings') },
        { label: t_i18n('Index metrics'), current: true },
      ]}
      />
      <IndexMetricsSummary />
      <IndexMetricsTable />
    </div>
  );
};

const IndexMetrics = () => {
  const { t_i18n } = useFormatter();
  const { setTitle } = useConnectedDocumentModifier();
  setTitle(t_i18n('Index metrics'));

  return (
    <Suspense fallback={<Loader variant={LoaderVariant.container} />}>
      <IndexMetricsComponent />
    </Suspense>
  );
};

export default IndexMetrics;
