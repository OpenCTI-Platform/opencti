import React, { Suspense, useState } from 'react';
import { graphql, PreloadedQuery, usePreloadedQuery } from 'react-relay';
import { Link } from 'react-router';
import { Box, List, ListItem, ListItemIcon, ListItemText, Stack, Typography } from '@mui/material';
import { useTheme } from '@mui/material/styles';
import { Chip, Tooltip, TooltipContent, TooltipTrigger } from '@filigran/design-system';
import type { Theme } from '../../../../components/Theme';
import Button from '@common/button/Button';
import Drawer from '@components/common/drawer/Drawer';
import Loader, { LoaderVariant } from '../../../../components/Loader';
import ItemIcon from '../../../../components/ItemIcon';
import { useFormatter } from '../../../../components/i18n';
import useQueryLoading from '../../../../utils/hooks/useQueryLoading';
import Security from '../../../../utils/Security';
import { KNOWLEDGE_KNUPDATE, SETTINGS_SETCUSTOMIZATION } from '../../../../utils/hooks/useGranted';
import { resolveLink } from '../../../../utils/Entity';
import { DefenseTechniqueDrawerQuery } from './__generated__/DefenseTechniqueDrawerQuery.graphql';
import DefenseValidationDialog from './DefenseValidationDialog';
import {
  DEFENSE_ACTION_LABELS,
  DEFENSE_DEPLOYMENT_STATUS_LABELS,
  DEFENSE_DETECTION_LABELS,
  DEFENSE_LEVEL_DESCRIPTIONS,
  DEFENSE_LEVEL_DETECTION_AVAILABLE,
  DEFENSE_LEVEL_DETECTION_DEPLOYED,
  DEFENSE_LEVEL_NONE,
  DEFENSE_LEVEL_TELEMETRY,
  DEFENSE_LEVEL_VALIDATED,
  DEFENSE_VALIDATION_LABELS,
  type DefenseAction,
  type DefenseDetection,
  type DefenseScopeState,
  type DefenseValidation,
  defenseLevelColor,
  defenseLevelLabel,
  isDisplayedValidationFailed,
  scopedDefensePlatforms,
  toThreatScopeInput,
} from './defenseMatrix-utils';

export const defenseTechniqueDrawerQuery = graphql`
  query DefenseTechniqueDrawerQuery($id: String!, $platformIds: [String!], $threatScope: DefenseThreatScope) {
    defensePlatforms {
      id
      name
      entity_type
    }
    defenseCoverageStatus {
      validation_available
    }
    defenseTechnique(id: $id, platformIds: $platformIds, threatScope: $threatScope) {
      computed_at
      attackPattern {
        id
        name
        x_mitre_id
      }
      cell {
        level
        telemetry
        detection
        validated
        last_result_at
        mitigated
        recommended_action
        threats_count
        platforms {
          platform_id
          level
          telemetry
          detection
          validated
          last_result_at
          recommended_action
          data_components_count
          rules_count
          results_count
        }
      }
      dataComponents {
        dataComponent {
          id
          name
        }
        providedBy {
          id
          name
        }
        inferredBy {
          id
          name
        }
      }
      rules {
        indicator {
          id
          name
          pattern_type
          x_opencti_rule_status
          x_opencti_rule_level
        }
        deployments {
          platform {
            id
            name
          }
          status
        }
      }
      validations {
        result {
          id
          representative {
            main
          }
        }
        securityCoverage {
          id
          name
        }
        status
        last_result_at
        scores {
          coverage_name
          coverage_score
        }
        platforms {
          platform {
            id
            name
          }
          status
        }
      }
      mitigations {
        id
        name
        x_mitre_id
      }
      threats {
        relationship_id
        confidence
        threat {
          id
          entity_type
          representative {
            main
          }
        }
      }
      gaps {
        id
        platform_id
        level
        recommended_action
        priority
        validation_requests {
          security_coverage_id
          requested_at
          status
          securityCoverage {
            id
            name
          }
        }
      }
    }
  }
`;

const LevelChip = ({ level }: { level: number }) => {
  const { t_i18n } = useFormatter();
  const theme = useTheme<Theme>();
  return <Chip label={defenseLevelLabel(t_i18n, level)} color={defenseLevelColor(theme, level)} />;
};

// Deployment statuses of a rule running on its security platform
const LIVE_DEPLOYMENT_STATUSES = ['active', 'deployed'];
const uniq = (values: string[]) => Array.from(new Set(values));

const Section = ({ title, count, children }: { title: string; count?: number; children: React.ReactNode }) => (
  <Box component="section" sx={{ marginTop: 3 }}>
    <Typography variant="h4" gutterBottom>
      {count === undefined ? title : `${title} (${count})`}
    </Typography>
    {children}
  </Box>
);

const Empty = ({ text }: { text: string }) => (
  <Typography variant="body2" color="text.secondary">{text}</Typography>
);

// Relative date, the full date on hover and focus
const RelativeDate = ({ date }: { date: string }) => {
  const { fldt, rd } = useFormatter();
  return (
    <Tooltip>
      <TooltipTrigger asChild>
        <span tabIndex={0} style={{ cursor: 'help' }}>{rd(date)}</span>
      </TooltipTrigger>
      <TooltipContent>{fldt(date)}</TooltipContent>
    </Tooltip>
  );
};

interface DefenseTechniqueContentProps {
  queryRef: PreloadedQuery<DefenseTechniqueDrawerQuery>;
  scope: DefenseScopeState;
  allowValidation: boolean;
}

const DefenseTechniqueContent = ({ queryRef, scope, allowValidation }: DefenseTechniqueContentProps) => {
  const { t_i18n, fld, fldt, rd } = useFormatter();
  const { defenseTechnique, defensePlatforms, defenseCoverageStatus } = usePreloadedQuery(defenseTechniqueDrawerQuery, queryRef);
  const [validating, setValidating] = useState(false);
  // As in the matrix header, validation is offered only while an OpenAEV connector is active
  const validationAvailable = !!defenseCoverageStatus?.validation_available;
  if (!defenseTechnique) {
    return <Empty text={t_i18n('This technique cannot be found.')} />;
  }
  const { attackPattern, cell } = defenseTechnique;
  const platformName = (id: string) => (id === 'all' ? t_i18n('All platforms') : defensePlatforms.find((p) => p.id === id)?.name ?? id);
  // A saved platform that was deleted or is no longer visible is left out, as the matrix itself does
  const validationPlatforms = scopedDefensePlatforms(scope.platformIds, defensePlatforms);

  // The evidence behind the level, said in one sentence
  const liveDeployments = defenseTechnique.rules.flatMap(({ indicator, deployments }) => deployments
    .filter((deployment) => LIVE_DEPLOYMENT_STATUSES.includes(deployment.status))
    .map((deployment) => ({ ruleId: indicator.id, platform: deployment.platform.name })));
  const liveRulesCount = uniq(liveDeployments.map((deployment) => deployment.ruleId)).length;
  const livePlatforms = uniq(liveDeployments.map((deployment) => deployment.platform)).join(', ');
  const collected = defenseTechnique.dataComponents.filter((dc) => dc.providedBy.length + dc.inferredBy.length > 0);
  const collectingPlatforms = uniq(collected.flatMap((dc) => [...dc.providedBy, ...dc.inferredBy].map((platform) => platform.name))).join(', ');
  const resultDate = cell.last_result_at ? fld(cell.last_result_at) : t_i18n('an unknown date');
  const failed = cell.validated === 'failed';
  const latestValidation = [...defenseTechnique.validations]
    .filter((validation) => (failed ? isDisplayedValidationFailed(validation) : true) && !!validation.securityCoverage)
    .sort((a, b) => (b.last_result_at ?? '').localeCompare(a.last_result_at ?? ''))[0];
  const explanation = (): string => {
    if (failed) {
      return t_i18n('The latest OpenAEV validation failed on {date}: the detection needs a fix.', { values: { date: resultDate } });
    }
    if (cell.level === DEFENSE_LEVEL_VALIDATED) {
      return liveRulesCount > 0
        ? t_i18n('Detected by {count, plural, one {# rule} other {# rules}} deployed on {platforms}, validated on {date}.', { values: { count: liveRulesCount, platforms: livePlatforms, date: resultDate } })
        : t_i18n('Validated by OpenAEV on {date}.', { values: { date: resultDate } });
    }
    if (cell.level === DEFENSE_LEVEL_DETECTION_DEPLOYED) {
      return t_i18n('Detected by {count, plural, one {# rule} other {# rules}} deployed on {platforms}, not validated yet.', { values: { count: liveRulesCount, platforms: livePlatforms } });
    }
    if (cell.level === DEFENSE_LEVEL_DETECTION_AVAILABLE) {
      return t_i18n('{count, plural, one {# detection rule is available} other {# detection rules are available}}, deployed on no security platform yet.', { values: { count: defenseTechnique.rules.length } });
    }
    if (cell.level === DEFENSE_LEVEL_TELEMETRY) {
      return t_i18n('Collected by {platforms} through {count, plural, one {# data component} other {# data components}}, no detection rule yet.', { values: { count: collected.length, platforms: collectingPlatforms } });
    }
    return t_i18n(DEFENSE_LEVEL_DESCRIPTIONS[DEFENSE_LEVEL_NONE]);
  };

  // The next action of the level
  const firstRule = defenseTechnique.rules[0]?.indicator;
  const nextAction = (): React.ReactNode => {
    if (failed) {
      return latestValidation?.securityCoverage ? (
        <Button component={Link} to={`/dashboard/analyses/security_coverages/${latestValidation.securityCoverage.id}`} data-testid="defense-technique-next-action">
          {t_i18n('Open the validation')}
        </Button>
      ) : null;
    }
    if (cell.level === DEFENSE_LEVEL_DETECTION_DEPLOYED && validationAvailable) {
      return (
        <Security needs={[KNOWLEDGE_KNUPDATE]}>
          <Button onClick={() => setValidating(true)} data-testid="defense-technique-validate">{t_i18n('Validate in OpenAEV')}</Button>
        </Security>
      );
    }
    if (cell.level === DEFENSE_LEVEL_DETECTION_AVAILABLE && firstRule) {
      return (
        <Button component={Link} to={`/dashboard/observations/indicators/${firstRule.id}`} data-testid="defense-technique-next-action">
          {t_i18n('Deploy the rule')}
        </Button>
      );
    }
    if (cell.level === DEFENSE_LEVEL_TELEMETRY) {
      return (
        <Button component={Link} to={`/dashboard/techniques/attack_patterns/${attackPattern.id}/knowledge/indicators`} data-testid="defense-technique-next-action">
          {t_i18n('Find a detection rule')}
        </Button>
      );
    }
    if (cell.level === DEFENSE_LEVEL_NONE) {
      const platformsButton = (
        <Button component={Link} to="/dashboard/entities/security_platforms" data-testid="defense-technique-next-action">
          {t_i18n('Map telemetry')}
        </Button>
      );
      return (
        <Security needs={[SETTINGS_SETCUSTOMIZATION]} placeholder={platformsButton}>
          <Button component={Link} to="/dashboard/settings/customization/telemetry_mappings" data-testid="defense-technique-next-action">
            {t_i18n('Map telemetry')}
          </Button>
        </Security>
      );
    }
    return null;
  };
  return (
    <Box data-testid="defense-technique-drawer-content">
      <Stack direction="row" spacing={1} alignItems="center" flexWrap="wrap" useFlexGap>
        <LevelChip level={cell.level} />
        <Chip label={t_i18n(DEFENSE_DETECTION_LABELS[cell.detection as DefenseDetection])} />
        <Chip
          label={t_i18n(DEFENSE_VALIDATION_LABELS[cell.validated as DefenseValidation])}
          severity={failed ? 'critical' : 'neutral'}
        />
        {cell.mitigated && <Chip label={t_i18n('Mitigated')} />}
      </Stack>
      <Typography variant="body1" sx={{ marginTop: 2 }} data-testid="defense-technique-explanation">
        {explanation()}
      </Typography>
      {defenseTechnique.computed_at && (
        <Tooltip>
          <TooltipTrigger asChild>
            <Typography variant="caption" color="text.secondary" tabIndex={0} sx={{ cursor: 'help' }}>
              {t_i18n('Computed {date}', { values: { date: rd(defenseTechnique.computed_at) } })}
            </Typography>
          </TooltipTrigger>
          <TooltipContent>{fldt(defenseTechnique.computed_at)}</TooltipContent>
        </Tooltip>
      )}
      <Stack direction="row" spacing={1} sx={{ marginTop: 2 }}>
        {nextAction()}
        <Button
          variant="secondary"
          component={Link}
          to={`/dashboard/techniques/attack_patterns/${attackPattern.id}`}
        >
          {t_i18n('Open the attack pattern')}
        </Button>
        {allowValidation && validationAvailable && cell.level !== DEFENSE_LEVEL_DETECTION_DEPLOYED && (
          <Security needs={[KNOWLEDGE_KNUPDATE]}>
            <Button variant="secondary" onClick={() => setValidating(true)} data-testid="defense-technique-validate">
              {t_i18n('Validate in OpenAEV')}
            </Button>
          </Security>
        )}
      </Stack>

      <Section title={t_i18n('Security platforms')} count={cell.platforms.length}>
        {cell.platforms.length === 0 ? <Empty text={t_i18n('No security platform is known.')} /> : (
          <List dense disablePadding>
            {cell.platforms.map((platform) => (
              <ListItem key={platform.platform_id} divider disableGutters>
                <ListItemIcon><ItemIcon type="SecurityPlatform" /></ListItemIcon>
                <ListItemText
                  primary={platformName(platform.platform_id)}
                  secondary={[
                    platform.telemetry ? t_i18n('Telemetry') : t_i18n('No telemetry'),
                    t_i18n(DEFENSE_DETECTION_LABELS[platform.detection as DefenseDetection]),
                    t_i18n(DEFENSE_VALIDATION_LABELS[platform.validated as DefenseValidation]),
                    t_i18n(DEFENSE_ACTION_LABELS[platform.recommended_action as DefenseAction]),
                  ].join(' - ')}
                />
                <LevelChip level={platform.level} />
              </ListItem>
            ))}
          </List>
        )}
      </Section>

      <Section title={t_i18n('Telemetry')} count={defenseTechnique.dataComponents.length}>
        {defenseTechnique.dataComponents.length === 0 ? <Empty text={t_i18n('No data component detects this technique.')} /> : (
          <List dense disablePadding>
            {defenseTechnique.dataComponents.map(({ dataComponent, providedBy, inferredBy }) => (
              <ListItem key={dataComponent.id} divider disableGutters>
                <ListItemIcon><ItemIcon type="Data-Component" /></ListItemIcon>
                <ListItemText
                  primary={<Link to={`/dashboard/techniques/data_components/${dataComponent.id}`}>{dataComponent.name}</Link>}
                  secondary={[
                    providedBy.length > 0 ? `${t_i18n('Provided by')} ${providedBy.map((p) => p.name).join(', ')}` : t_i18n('Not provided by any security platform'),
                    inferredBy.length > 0 ? `${t_i18n('Inferred from deployed rules on')} ${inferredBy.map((p) => p.name).join(', ')}` : null,
                  ].filter(Boolean).join(' - ')}
                />
              </ListItem>
            ))}
          </List>
        )}
      </Section>

      <Section title={t_i18n('Detection rules')} count={defenseTechnique.rules.length}>
        {defenseTechnique.rules.length === 0 ? <Empty text={t_i18n('No detection rule indicates this technique.')} /> : (
          <List dense disablePadding>
            {defenseTechnique.rules.map(({ indicator, deployments }) => (
              <ListItem key={indicator.id} divider disableGutters>
                <ListItemIcon><ItemIcon type="Indicator" /></ListItemIcon>
                <ListItemText
                  primary={<Link to={`/dashboard/observations/indicators/${indicator.id}`}>{indicator.name}</Link>}
                  secondary={[
                    indicator.pattern_type,
                    indicator.x_opencti_rule_status,
                    indicator.x_opencti_rule_level,
                    deployments.length > 0
                      ? deployments.map((d) => `${d.platform.name}: ${t_i18n(DEFENSE_DEPLOYMENT_STATUS_LABELS[d.status] ?? d.status)}`).join(', ')
                      : t_i18n('Not deployed'),
                  ].filter(Boolean).join(' - ')}
                />
              </ListItem>
            ))}
          </List>
        )}
      </Section>

      <Section title={t_i18n('OpenAEV validations')} count={defenseTechnique.validations.length}>
        {defenseTechnique.validations.length === 0 ? <Empty text={t_i18n('No OpenAEV result covers this technique.')} /> : (
          <List dense disablePadding>
            {defenseTechnique.validations.map((validation) => (
              <ListItem key={validation.result.id} divider disableGutters>
                <ListItemIcon><ItemIcon type="Security-Coverage" /></ListItemIcon>
                <ListItemText
                  primary={validation.securityCoverage ? (
                    <Link to={`/dashboard/analyses/security_coverages/${validation.securityCoverage.id}`}>{validation.securityCoverage.name}</Link>
                  ) : validation.result.representative.main}
                  secondary={(
                    <>
                      {[
                        t_i18n(DEFENSE_VALIDATION_LABELS[validation.status as DefenseValidation]),
                        validation.scores.map((s) => `${t_i18n(s.coverage_name)} ${s.coverage_score}%`).join(', '),
                        // A platform's status is only repeated when it differs from the result's
                        validation.platforms.map((p) => (p.status === validation.status
                          ? p.platform.name
                          : `${p.platform.name}: ${t_i18n(DEFENSE_VALIDATION_LABELS[p.status as DefenseValidation])}`)).join(', '),
                      ].filter((part) => !!part).join(' - ')}
                      {validation.last_result_at && (
                        <>
                          {' - '}
                          <RelativeDate date={validation.last_result_at} />
                        </>
                      )}
                    </>
                  )}
                />
              </ListItem>
            ))}
          </List>
        )}
      </Section>

      <Section title={t_i18n('Mitigations')} count={defenseTechnique.mitigations.length}>
        {defenseTechnique.mitigations.length === 0 ? <Empty text={t_i18n('No course of action mitigates this technique.')} /> : (
          <List dense disablePadding>
            {defenseTechnique.mitigations.map((mitigation) => (
              <ListItem key={mitigation.id} divider disableGutters>
                <ListItemIcon><ItemIcon type="Course-Of-Action" /></ListItemIcon>
                <ListItemText
                  primary={(
                    <Link to={`/dashboard/techniques/courses_of_action/${mitigation.id}`}>
                      {mitigation.x_mitre_id ? `[${mitigation.x_mitre_id}] ${mitigation.name}` : mitigation.name}
                    </Link>
                  )}
                />
              </ListItem>
            ))}
          </List>
        )}
      </Section>

      <Section title={t_i18n('Threats using this technique')} count={defenseTechnique.threats.length}>
        {defenseTechnique.threats.length === 0 ? <Empty text={t_i18n('No threat of the overlay uses this technique.')} /> : (
          <List dense disablePadding>
            {defenseTechnique.threats.map(({ threat, relationship_id: relationshipId, confidence }) => (
              <ListItem key={relationshipId} divider disableGutters>
                <ListItemIcon><ItemIcon type={threat.entity_type} /></ListItemIcon>
                <ListItemText
                  primary={<Link to={`${resolveLink(threat.entity_type)}/${threat.id}`}>{threat.representative.main}</Link>}
                  secondary={`${t_i18n('Confidence')} ${confidence}`}
                />
              </ListItem>
            ))}
          </List>
        )}
      </Section>

      <Section title={t_i18n('Validation requests')}>
        {defenseTechnique.gaps.every((gap) => gap.validation_requests.length === 0) ? <Empty text={t_i18n('No validation was requested for this technique.')} /> : (
          <List dense disablePadding>
            {defenseTechnique.gaps.flatMap((gap) => gap.validation_requests.map((request) => (
              <ListItem key={`${gap.id}-${request.security_coverage_id}`} divider disableGutters>
                <ListItemIcon><ItemIcon type="Security-Coverage" /></ListItemIcon>
                <ListItemText
                  primary={request.securityCoverage ? (
                    <Link to={`/dashboard/analyses/security_coverages/${request.securityCoverage.id}`}>{request.securityCoverage.name}</Link>
                  ) : t_i18n('Restricted security coverage')}
                  secondary={(
                    <>
                      {`${platformName(gap.platform_id)} - `}
                      <RelativeDate date={request.requested_at} />
                      {request.status !== 'results' && (
                        <Typography component="span" variant="body2" display="block" color={request.status === 'waiting' ? 'warning.main' : 'text.secondary'} data-testid="defense-validation-request-status">
                          {request.status === 'waiting'
                            ? t_i18n('Waiting for OpenAEV: no OpenAEV platform has read the security coverages yet')
                            : t_i18n('Read by OpenAEV, waiting for the first results')}
                        </Typography>
                      )}
                    </>
                  )}
                />
              </ListItem>
            )))}
          </List>
        )}
      </Section>

      <DefenseValidationDialog
        open={validating}
        onClose={() => setValidating(false)}
        techniques={[{ id: attackPattern.id, name: attackPattern.name, x_mitre_id: attackPattern.x_mitre_id }]}
        platforms={validationPlatforms}
        threats={scope.threatMode === 'SELECTED' ? scope.threats : []}
      />
    </Box>
  );
};

interface DefenseTechniqueDrawerProps {
  attackPatternId: string | null;
  title: string;
  scope: DefenseScopeState;
  onClose: () => void;
  // The validation action belongs to the gap context (Gaps tab), not to the matrix
  allowValidation?: boolean;
}

const DefenseTechniqueLoader = ({ attackPatternId, scope, allowValidation }: { attackPatternId: string; scope: DefenseScopeState; allowValidation: boolean }) => {
  const queryRef = useQueryLoading<DefenseTechniqueDrawerQuery>(defenseTechniqueDrawerQuery, {
    id: attackPatternId,
    platformIds: scope.platformIds,
    threatScope: toThreatScopeInput(scope),
  });
  return queryRef ? (
    <Suspense fallback={<Loader variant={LoaderVariant.inElement} />}>
      <DefenseTechniqueContent queryRef={queryRef} scope={scope} allowValidation={allowValidation} />
    </Suspense>
  ) : <Loader variant={LoaderVariant.inElement} />;
};

const DefenseTechniqueDrawer = ({ attackPatternId, title, scope, onClose, allowValidation = false }: DefenseTechniqueDrawerProps) => (
  <Drawer open={!!attackPatternId} title={title} onClose={onClose} size="large">
    {attackPatternId ? <DefenseTechniqueLoader attackPatternId={attackPatternId} scope={scope} allowValidation={allowValidation} /> : <div />}
  </Drawer>
);

export default DefenseTechniqueDrawer;
