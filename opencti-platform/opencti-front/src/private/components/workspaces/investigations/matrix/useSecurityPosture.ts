import { useEffect } from 'react';
import type { EntityOption } from '@components/common/form/EntitySelect';
import useShouldCoverOverlap from '@components/common/stix_domain_objects/useShouldCoverOverlap';
import { useFormatter } from '../../../../../components/i18n';
import { MESSAGING$ } from '../../../../../relay/environment';
import type { InvestigationMatrixSettingsChange } from './investigationMatrixSettings';

/**
 * The security posture of the matrix: the attack patterns the chosen security platforms should cover.
 * `attackPatternIdsToOverlap` is undefined while no platform is chosen: the lookup gives [] then, which would mark every cell.
 */
const useSecurityPosture = (securityPlatforms: EntityOption[], onSettingsChange: InvestigationMatrixSettingsChange) => {
  const { t_i18n } = useFormatter();
  const { attackPatternIdsToOverlap, setSecurityPlatformIds, error } = useShouldCoverOverlap();

  useEffect(() => {
    // Back from the graph view: the posture marks of the platforms chosen before are looked up again.
    if (securityPlatforms.length > 0) {
      setSecurityPlatformIds(securityPlatforms.map(({ value }) => value));
    }
  }, []);

  useEffect(() => {
    // Once per failed lookup: the matrix keeps rendering, without posture marks.
    if (error) MESSAGING$.notifyError(t_i18n('The security posture could not be loaded'));
  }, [error]);

  const onSecurityPlatformsChange = async (platforms: EntityOption[]) => {
    onSettingsChange({ securityPlatforms: platforms });
    await setSecurityPlatformIds(platforms.map(({ value }) => value));
  };

  return {
    attackPatternIdsToOverlap: securityPlatforms.length > 0 ? attackPatternIdsToOverlap : undefined,
    onSecurityPlatformsChange,
  };
};

export default useSecurityPosture;
