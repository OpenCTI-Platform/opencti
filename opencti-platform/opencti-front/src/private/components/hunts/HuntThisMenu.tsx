import React, { useState } from 'react';
import { graphql } from 'react-relay';
import { AutoAwesomeOutlined, ExpandMoreOutlined } from '@mui/icons-material';
import { Crosshairs } from 'mdi-material-ui';
import { Button, Menu, MenuContent, MenuItem, MenuTrigger, Tooltip, TooltipContent, TooltipTrigger } from '@filigran/design-system';
import { useFormatter } from '../../../components/i18n';
import { fetchQuery, MESSAGING$ } from '../../../relay/environment';
import Security from '../../../utils/Security';
import { KNOWLEDGE_KNUPDATE } from '../../../utils/hooks/useGranted';
import { useIsHiddenEntities } from '../../../utils/hooks/useEntitySettings';
import useDraftContext from '../../../utils/hooks/useDraftContext';
import { HuntCreationDrawer } from './HuntCreation';
import HuntPlanDialog from './HuntPlanDialog';
import useHuntAI from './useHuntAI';
import { buildHuntPrefill, buildHuntPrefillName, HUNT_TARGET_TYPES, HUNT_TECHNIQUE_TYPES, HuntFormValues, HuntPrefillEntity } from './hunt-utils';
import { HuntThisMenuContainerObjectsQuery } from './__generated__/HuntThisMenuContainerObjectsQuery.graphql';
import { HuntThisMenuPirEntitiesQuery } from './__generated__/HuntThisMenuPirEntitiesQuery.graphql';

const PREFILL_MAX_ENTITIES = 100;

const huntThisMenuContainerObjectsQuery = graphql`
  query HuntThisMenuContainerObjectsQuery($id: String!, $types: [String], $first: Int) {
    container(id: $id) {
      id
      objects(types: $types, first: $first) {
        edges {
          node {
            ... on StixDomainObject {
              id
              entity_type
              representative {
                main
              }
            }
          }
        }
      }
    }
  }
`;

const huntThisMenuPirEntitiesQuery = graphql`
  query HuntThisMenuPirEntitiesQuery($types: [String], $first: Int, $filters: FilterGroup) {
    stixDomainObjects(types: $types, first: $first, filters: $filters) {
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

/** Targets, techniques and sources a hunt created from the entity starts with. */
const fetchHuntPrefill = async (entity: HuntPrefillEntity): Promise<Partial<HuntFormValues>> => {
  const name = buildHuntPrefillName(entity.name);
  if (entity.entity_type === 'Report') {
    const data = await fetchQuery<HuntThisMenuContainerObjectsQuery>(huntThisMenuContainerObjectsQuery, {
      id: entity.id,
      types: [...HUNT_TARGET_TYPES, ...HUNT_TECHNIQUE_TYPES],
      first: PREFILL_MAX_ENTITIES,
    }).toPromise();
    const objects = toPrefillEntities((data?.container?.objects?.edges ?? []).map((edge) => edge?.node));
    return { name, ...buildHuntPrefill([entity, ...objects]) };
  }
  if (entity.entity_type === 'Pir') {
    const data = await fetchQuery<HuntThisMenuPirEntitiesQuery>(huntThisMenuPirEntitiesQuery, {
      types: HUNT_TARGET_TYPES,
      first: PREFILL_MAX_ENTITIES,
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
    return { name, ...buildHuntPrefill(toPrefillEntities((data?.stixDomainObjects?.edges ?? []).map((edge) => edge?.node))) };
  }
  return { name, ...buildHuntPrefill([entity]) };
};

interface HuntThisMenuProps {
  entity: HuntPrefillEntity;
}

/** "Hunt this" quick action of the threat, technique, report, indicator and PIR pages. */
const HuntThisMenu = ({ entity }: HuntThisMenuProps) => {
  const { t_i18n } = useFormatter();
  const draftContext = useDraftContext();
  const huntHidden = useIsHiddenEntities('Hunt');
  const { available: aiAvailable, isEnterpriseEdition } = useHuntAI();
  const [prefill, setPrefill] = useState<Partial<HuntFormValues> | null>(null);
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

  return (
    <Security needs={[KNOWLEDGE_KNUPDATE]}>
      <>
        <Menu>
          <MenuTrigger asChild>
            <Button
              priority="secondary"
              size="sm"
              startIcon={<Crosshairs fontSize="small" />}
              endIcon={<ExpandMoreOutlined fontSize="small" />}
              data-testid="hunt-this-menu"
            >
              {t_i18n('Hunt this')}
            </Button>
          </MenuTrigger>
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
          <HuntCreationDrawer open onClose={() => setPrefill(null)} initialValues={prefill} />
        )}
        <HuntPlanDialog open={planOpen} onClose={() => setPlanOpen(false)} entityIds={[entity.id]} />
      </>
    </Security>
  );
};

export default HuntThisMenu;
