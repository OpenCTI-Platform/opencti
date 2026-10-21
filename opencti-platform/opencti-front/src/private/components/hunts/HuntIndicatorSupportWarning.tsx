import React, { Suspense } from 'react';
import { graphql, useLazyLoadQuery } from 'react-relay';
import { Alert } from '@filigran/design-system';
import { useFormatter } from '../../../components/i18n';
import { HuntIndicatorSupportWarningQuery } from './__generated__/HuntIndicatorSupportWarningQuery.graphql';

const huntIndicatorSupportWarningQuery = graphql`
  query HuntIndicatorSupportWarningQuery {
    huntConnectors(onlyAlive: true) {
      id
      supports_indicators
      securityPlatform {
        id
      }
    }
  }
`;

interface HuntIndicatorSupportWarningProps {
  /** The security platforms of the scope of the hunt, empty for every platform */
  scopePlatformIds: string[];
  style?: React.CSSProperties;
}

/** Whether any live hunt connector of the scope looks up indicators: none can run an indicator hunt otherwise. */
export const hasIndicatorLookups = (
  connectors: ReadonlyArray<{ supports_indicators: boolean | null | undefined; securityPlatform: { id: string } | null | undefined }>,
  scopePlatformIds: string[],
) => connectors.some((connector) => !!connector.supports_indicators
  && !!connector.securityPlatform
  && (scopePlatformIds.length === 0 || scopePlatformIds.includes(connector.securityPlatform.id)));

const Warning = ({ scopePlatformIds, style }: HuntIndicatorSupportWarningProps) => {
  const { t_i18n } = useFormatter();
  const { huntConnectors } = useLazyLoadQuery<HuntIndicatorSupportWarningQuery>(huntIndicatorSupportWarningQuery, {}, { fetchPolicy: 'store-and-network' });
  if (hasIndicatorLookups(huntConnectors, scopePlatformIds)) {
    return null;
  }
  return (
    <div style={style} data-testid="hunt-indicator-support-warning">
      <Alert
        severity="warning"
        title={t_i18n('No hunt connector of the scope looks up indicators')}
        description={t_i18n('The hunt can be saved, but it cannot run until a hunt connector of its scope supports indicator lookups. A Sigma rule or a native query runs on every hunt connector.')}
      />
    </div>
  );
};

/** Warns, before an indicator hunt is created, that no hunt connector of its scope could run it. */
const HuntIndicatorSupportWarning = (props: HuntIndicatorSupportWarningProps) => (
  <Suspense fallback={null}>
    <Warning {...props} />
  </Suspense>
);

export default HuntIndicatorSupportWarning;
