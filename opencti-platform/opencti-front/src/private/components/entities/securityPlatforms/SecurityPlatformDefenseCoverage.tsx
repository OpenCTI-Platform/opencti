import React, { Suspense, useState } from 'react';
import { useNavigate } from 'react-router';
import { Stack } from '@mui/material';
import Button from '@common/button/Button';
import { PATH_DEFENSE_GAPS } from '@components/common/routes/paths';
import DefenseProvidedDataComponents from '@components/defense/matrix/DefenseProvidedDataComponents';
import DefenseScopeToolbar from '@components/defense/matrix/DefenseScopeToolbar';
import { DefenseMatrixContent, defenseMatrixQuery } from '@components/defense/matrix/DefenseMatrix';
import useDefenseScope from '@components/defense/matrix/useDefenseScope';
import { ALL_DEFENSE_LAYERS, type DefenseLayersState, type DefenseScopeState, toThreatScopeInput } from '@components/defense/matrix/defenseMatrix-utils';
import { DefenseMatrixQuery } from '@components/defense/matrix/__generated__/DefenseMatrixQuery.graphql';
import Card from '../../../../components/common/card/Card';
import Loader, { LoaderVariant } from '../../../../components/Loader';
import { useFormatter } from '../../../../components/i18n';
import useQueryLoading from '../../../../utils/hooks/useQueryLoading';

interface SecurityPlatformDefenseCoverageProps {
  securityPlatformId: string;
}

/**
 * Defense posture of one security platform: the telemetry it provides, and the defense matrix
 * restricted to its telemetry, deployed rules and OpenAEV results, with the shared threat overlay.
 */
const SecurityPlatformDefenseCoverage = ({ securityPlatformId }: SecurityPlatformDefenseCoverageProps) => {
  const { t_i18n } = useFormatter();
  const navigate = useNavigate();
  const [sharedScope, setSharedScope] = useDefenseScope();
  const [layers, setLayers] = useState<DefenseLayersState>(ALL_DEFENSE_LAYERS);
  const scope: DefenseScopeState = { ...sharedScope, platformIds: [securityPlatformId] };
  const queryRef = useQueryLoading<DefenseMatrixQuery>(defenseMatrixQuery, {
    platformIds: [securityPlatformId],
    threatScope: toThreatScopeInput(scope),
  });
  const updateThreatScope = (next: DefenseScopeState) => setSharedScope({ ...next, platformIds: sharedScope.platformIds });
  const openGaps = () => {
    setSharedScope({ ...sharedScope, platformIds: [securityPlatformId] });
    navigate(PATH_DEFENSE_GAPS);
  };

  return (
    <Stack spacing={3} data-testid="security-platform-defense-coverage">
      <DefenseProvidedDataComponents entityId={securityPlatformId} />
      <Card
        title={t_i18n('Threat overlay and layers')}
        action={(
          <Button variant="secondary" onClick={openGaps} data-testid="security-platform-defense-gaps">
            {t_i18n('View the gaps of this platform')}
          </Button>
        )}
      >
        <DefenseScopeToolbar
          platforms={[]}
          hidePlatforms
          scope={scope}
          onScopeChange={updateThreatScope}
          layers={layers}
          onLayersChange={setLayers}
        />
      </Card>
      {queryRef && (
        <Suspense fallback={<Loader variant={LoaderVariant.inElement} />}>
          <DefenseMatrixContent queryRef={queryRef} scope={scope} layers={layers} />
        </Suspense>
      )}
    </Stack>
  );
};

export default SecurityPlatformDefenseCoverage;
