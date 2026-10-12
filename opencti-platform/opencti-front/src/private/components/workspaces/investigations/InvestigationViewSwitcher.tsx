import React from 'react';
import { ButtonGroup, ButtonGroupItem, Tooltip, TooltipContent, TooltipTrigger } from '@filigran/design-system';
import { ViewColumnOutlined } from '@mui/icons-material';
import { VectorPolygon } from 'mdi-material-ui';
import { Link, useLocation } from 'react-router';
import { useFormatter } from '../../../../components/i18n';

export const INVESTIGATION_MATRIX_EXPORT_ID = 'investigation-matrix-export';

export type InvestigationView = 'graph' | 'matrix';

/**
 * The route is the state: a path ending in `/matrix` selects the matrix,
 * anything else selects the graph.
 */
export const useInvestigationView = (): InvestigationView => {
  const { pathname } = useLocation();
  return /\/matrix\/?$/.test(pathname) ? 'matrix' : 'graph';
};

const InvestigationViewSwitcher = ({ investigationId }: { investigationId: string }) => {
  const { t_i18n } = useFormatter();
  const view = useInvestigationView();
  const link = `/dashboard/workspaces/investigations/${investigationId}`;

  return (
    <div id="investigation-view-buttons">
      {/* Each segment NAVIGATES, so it stays a real <a href> through `asChild`.
          No onValueChange: the route IS the state. */}
      <ButtonGroup
        size="md"
        value={view}
        aria-label={t_i18n('Change view')}
      >
        <Tooltip>
          <TooltipTrigger asChild>
            <ButtonGroupItem
              asChild
              value="graph"
              aria-label={t_i18n('Graph view')}
              icon={<VectorPolygon sx={{ fontSize: 16 }} />}
            >
              <Link to={link} />
            </ButtonGroupItem>
          </TooltipTrigger>
          <TooltipContent>{t_i18n('Graph view')}</TooltipContent>
        </Tooltip>
        <Tooltip>
          <TooltipTrigger asChild>
            <ButtonGroupItem
              asChild
              value="matrix"
              aria-label={t_i18n('Tactics matrix view')}
              icon={<ViewColumnOutlined sx={{ fontSize: 16 }} />}
            >
              <Link to={`${link}/matrix`} />
            </ButtonGroupItem>
          </TooltipTrigger>
          <TooltipContent>{t_i18n('Tactics matrix view')}</TooltipContent>
        </Tooltip>
      </ButtonGroup>
    </div>
  );
};

export default InvestigationViewSwitcher;
