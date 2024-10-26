import React, { FunctionComponent } from 'react';
import MUIBreadcrumbs from '@mui/material/Breadcrumbs';
import { Link } from 'react-router-dom';
import Typography from '@mui/material/Typography';
import { useTheme } from '@mui/styles';
import DangerZoneChip from '@components/common/danger_zone/DangerZoneChip';
import { truncate } from '../utils/String';
import type { Theme } from './Theme';

interface element {
  label: string;
  link?: string;
  current?: boolean;
}

interface BreadcrumbsProps {
  elements: element[]
  isSensitive?: boolean
}

const Breadcrumbs: FunctionComponent<BreadcrumbsProps> = ({ elements, isSensitive = false }) => {
  const theme = useTheme<Theme>();
  return (
    <MUIBreadcrumbs style={{ marginBottom: theme.spacing(2) }}>
      {elements.map((element) => {
        if (element.current) {
          return (
            <span key={element.label} style={{ display: 'flex', alignItems: 'center' }}>
              <Typography color={'text.primary'}>
                {truncate(element.label, 30, false)}
              </Typography>
              {isSensitive && <DangerZoneChip />}
            </span>
          );
        }
        if (!element.link) {
          return (
            <Typography key={element.label} color="inherit">{truncate(element.label, 30, false)}</Typography>
          );
        }
        return (
          <Link key={element.label} to={element.link}>{truncate(element.label, 30, false)}</Link>
        );
      })}
    </MUIBreadcrumbs>
  );
};

export default Breadcrumbs;
