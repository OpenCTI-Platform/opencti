import React from 'react';
import { ButtonGroup, ButtonGroupItem, Tooltip, TooltipContent, TooltipTrigger } from '@filigran/design-system';
import { ViewColumnOutlined } from '@mui/icons-material';
import { VectorPolygon } from 'mdi-material-ui';
import { Link, Navigate, useLocation } from 'react-router';
import { useFormatter } from '../../../../components/i18n';
import useGranted, { KNOWLEDGE } from '../../../../utils/hooks/useGranted';

export const INVESTIGATION_MATRIX_EXPORT_ID = 'investigation-matrix-export';

export type InvestigationView = 'graph' | 'matrix';

const isMatrixPath = (pathname: string) => /\/matrix\/?$/.test(pathname);

/**
 * An investigation only needs INVESTIGATION, but the matrix reads `attackPatternsMatrix` and searches
 * security platforms, both restricted to KNOWLEDGE. Without KNOWLEDGE there is no matrix view.
 */
export const useCanViewInvestigationMatrix = () => useGranted([KNOWLEDGE]);

/**
 * The route is the state: a path ending in `/matrix` selects the matrix,
 * anything else selects the graph. A user without KNOWLEDGE always gets the graph.
 */
export const useInvestigationView = (): InvestigationView => {
  const { pathname } = useLocation();
  const canViewMatrix = useCanViewInvestigationMatrix();
  return canViewMatrix && isMatrixPath(pathname) ? 'matrix' : 'graph';
};

const InvestigationViewSwitcher = ({ investigationId }: { investigationId: string }) => {
  const { t_i18n } = useFormatter();
  const { pathname } = useLocation();
  const view = useInvestigationView();
  const canViewMatrix = useCanViewInvestigationMatrix();
  const link = `/dashboard/workspaces/investigations/${investigationId}`;

  // Without KNOWLEDGE the graph is the only view: no switch, and a `/matrix` link goes back to the graph.
  if (!canViewMatrix) {
    return isMatrixPath(pathname) ? <Navigate to={link} replace /> : null;
  }

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
              aria-label={t_i18n('Matrix view')}
              icon={<ViewColumnOutlined sx={{ fontSize: 16 }} />}
            >
              <Link to={`${link}/matrix`} />
            </ButtonGroupItem>
          </TooltipTrigger>
          <TooltipContent>{t_i18n('Matrix view')}</TooltipContent>
        </Tooltip>
      </ButtonGroup>
    </div>
  );
};

export default InvestigationViewSwitcher;
