import React, { useState } from 'react';
import { graphql } from 'react-relay';
import { AutoAwesomeOutlined } from '@mui/icons-material';
import { Crosshairs } from 'mdi-material-ui';
import { IconButton, Menu, MenuContent, MenuItem, MenuTrigger, Tooltip, TooltipContent, TooltipTrigger } from '@filigran/design-system';
import { useFormatter } from '../../../components/i18n';
import { fetchQuery, MESSAGING$ } from '../../../relay/environment';
import Security from '../../../utils/Security';
import { KNOWLEDGE_KNUPDATE } from '../../../utils/hooks/useGranted';
import { useIsHiddenEntities } from '../../../utils/hooks/useEntitySettings';
import useDraftContext from '../../../utils/hooks/useDraftContext';
import { HuntCreationDrawer } from './HuntCreation';
import { huntFromEntityDerivedQuery } from './HuntFromEntity';
import HuntPlanDialog from './HuntPlanDialog';
import useHuntAI from './useHuntAI';
import {
  buildDerivedHuntPrefill,
  buildHuntPrefill,
  buildHuntPrefillName,
  buildIndicatorHuntPrefill,
  buildIocHuntPrefill,
  HUNT_DERIVABLE_TYPES,
  HUNT_TARGET_TYPES,
  type HuntDerived,
  HuntFormValues,
  HuntIndicatorPrefillEntity,
  HuntPrefillEntity,
  isIocHuntEntity,
} from './hunt-utils';
import { HuntFromEntityDerivedQuery } from './__generated__/HuntFromEntityDerivedQuery.graphql';
import { HuntThisMenuPirEntitiesQuery } from './__generated__/HuntThisMenuPirEntitiesQuery.graphql';

const PREFILL_MAX_ENTITIES = 100;

const huntThisMenuPirEntitiesQuery = graphql`
  query HuntThisMenuPirEntitiesQuery($types: [String], $first: Int, $pirId: ID, $filters: FilterGroup) {
    stixDomainObjects(types: $types, first: $first, pirId: $pirId, orderBy: pir_score, orderMode: desc, filters: $filters) {
      pageInfo {
        globalCount
      }
      edges {
        node {
          id
          entity_type
          representative {
            main
          }
        }
      }
    }
  }
`;

type PrefillNode = { id?: string; entity_type?: string; representative?: { main: string } } | null | undefined;

const toPrefillEntities = (nodes: PrefillNode[]): HuntPrefillEntity[] => nodes
  .filter((node): node is { id: string; entity_type: string; representative: { main: string } } => !!node?.id && !!node.entity_type && !!node.representative)
  .map((node) => ({ id: node.id, entity_type: node.entity_type, name: node.representative.main }));

interface HuntThisPrefill {
  values: Partial<HuntFormValues>;
  derived: HuntDerived | null;
  /** For a PIR: how many threats it flags, and how many of them are prefilled */
  pirTargets?: { flagged: number; selected: number };
}

/** Without derived content (a PIR, or an entity the user cannot read): the entity and, for a PIR, the threats it flags. */
const fetchEntityPrefill = async (entity: HuntIndicatorPrefillEntity): Promise<Omit<HuntThisPrefill, 'derived'>> => {
  const name = buildHuntPrefillName(entity.name);
  if (entity.entity_type === 'Indicator') {
    return { values: { name, ...buildIndicatorHuntPrefill(entity) } };
  }
  if (isIocHuntEntity(entity.entity_type)) {
    return { values: { name, ...buildIocHuntPrefill(entity) } };
  }
  if (entity.entity_type === 'Pir') {
    // The flagged threats with the highest PIR score, as when a hunt is planned from the PIR
    const data = await fetchQuery<HuntThisMenuPirEntitiesQuery>(huntThisMenuPirEntitiesQuery, {
      types: HUNT_TARGET_TYPES,
      first: PREFILL_MAX_ENTITIES,
      pirId: entity.id,
      filters: {
        mode: 'and',
        filterGroups: [],
        filters: [{
          key: ['regardingOf'],
          values: [
            { key: 'relationship_type', values: ['in-pir'] },
            { key: 'id', values: [entity.id] },
          ],
        }],
      },
    }).toPromise();
    const prefill = buildHuntPrefill(toPrefillEntities((data?.stixDomainObjects?.edges ?? []).map((edge) => edge?.node)));
    const selected = prefill.huntTargets.length;
    return {
      values: { name, ...prefill },
      pirTargets: { flagged: Math.max(data?.stixDomainObjects?.pageInfo.globalCount ?? 0, selected), selected },
    };
  }
  return { values: { name, ...buildHuntPrefill([entity]) } };
};

/** The hunt created from the entity: what the platform derives from it (its indicators, techniques and detection rules). */
export const fetchHuntPrefill = async (entity: HuntIndicatorPrefillEntity): Promise<HuntThisPrefill> => {
  if (HUNT_DERIVABLE_TYPES.includes(entity.entity_type)) {
    const data = await fetchQuery<HuntFromEntityDerivedQuery>(huntFromEntityDerivedQuery, { entityId: entity.id }).toPromise();
    const derived = data?.huntDerivedContent ?? null;
    if (derived) {
      return { values: buildDerivedHuntPrefill(entity, derived), derived };
    }
  }
  return { ...(await fetchEntityPrefill(entity)), derived: null };
};

interface HuntThisMenuProps {
  entity: HuntIndicatorPrefillEntity;
}

/** "Hunt this" quick action of the threat, tool, technique, report, indicator, observable, grouping, case, incident and PIR pages. */
const HuntThisMenu = ({ entity }: HuntThisMenuProps) => {
  const { t_i18n } = useFormatter();
  const draftContext = useDraftContext();
  const huntHidden = useIsHiddenEntities('Hunt');
  const { available: aiAvailable, isEnterpriseEdition } = useHuntAI();
  const [prefill, setPrefill] = useState<HuntThisPrefill | null>(null);
  const [planOpen, setPlanOpen] = useState(false);

  if (huntHidden) return null;

  const createHunt = () => {
    fetchHuntPrefill(entity)
      .then(setPrefill)
      .catch(() => MESSAGING$.notifyError(t_i18n('The knowledge of this entity could not be loaded')));
  };

  let aiDisabledReason: string | null = null;
  if (draftContext) {
    aiDisabledReason = t_i18n('Not available in a draft');
  } else if (!isEnterpriseEdition) {
    aiDisabledReason = t_i18n('Enterprise Edition');
  } else if (!aiAvailable) {
    aiDisabledReason = t_i18n('XTM One is not configured');
  }
  const targetsHelperText = prefill?.pirTargets && prefill.pirTargets.flagged > prefill.pirTargets.selected
    ? t_i18n('The PIR flags {flagged} threats: the {selected} with the highest PIR score are prefilled', { values: prefill.pirTargets })
    : undefined;

  return (
    <Security needs={[KNOWLEDGE_KNUPDATE]}>
      <>
        <Menu>
          <Tooltip>
            <TooltipTrigger asChild>
              <MenuTrigger asChild>
                <IconButton
                  priority="tertiary"
                  size="sm"
                  aria-label={t_i18n('Hunt this')}
                  icon={<Crosshairs fontSize="small" />}
                  data-testid="hunt-this-menu"
                />
              </MenuTrigger>
            </TooltipTrigger>
            <TooltipContent>{t_i18n('Hunt this')}</TooltipContent>
          </Tooltip>
          <MenuContent align="end" aria-label={t_i18n('Hunt this')}>
            <MenuItem
              startIcon={<Crosshairs fontSize="small" />}
              onSelect={createHunt}
              data-testid="hunt-this-create"
            >
              {t_i18n('Create a hunt')}
            </MenuItem>
            {aiDisabledReason ? (
              <Tooltip>
                <TooltipTrigger asChild>
                  <span data-testid="hunt-this-plan-disabled-reason">
                    <MenuItem startIcon={<AutoAwesomeOutlined fontSize="small" />} disabled aria-description={aiDisabledReason} data-testid="hunt-this-plan">
                      {t_i18n('Plan a hunt with AI')}
                    </MenuItem>
                  </span>
                </TooltipTrigger>
                <TooltipContent>{aiDisabledReason}</TooltipContent>
              </Tooltip>
            ) : (
              <MenuItem startIcon={<AutoAwesomeOutlined fontSize="small" />} onSelect={() => setPlanOpen(true)} data-testid="hunt-this-plan">
                {t_i18n('Plan a hunt with AI')}
              </MenuItem>
            )}
          </MenuContent>
        </Menu>
        {prefill && (
          <HuntCreationDrawer
            open
            onClose={() => setPrefill(null)}
            initialValues={prefill.values}
            derived={prefill.derived}
            targetsHelperText={targetsHelperText}
          />
        )}
        <HuntPlanDialog open={planOpen} onClose={() => setPlanOpen(false)} entityIds={[entity.id]} />
      </>
    </Security>
  );
};

export default HuntThisMenu;
