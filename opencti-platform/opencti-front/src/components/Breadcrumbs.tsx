import React, { Fragment, FunctionComponent } from 'react';
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
  noMargin?: boolean
  isSensitive?: boolean
}

const Breadcrumbs: FunctionComponent<BreadcrumbsProps> = ({ elements, noMargin = false, isSensitive = false }) => {
  const theme = useTheme<Theme>();

  const SplitDiv = ({ show = true }) => (
    <div style={{ display: show ? 'none' : 'unset', marginLeft: theme.spacing(1), marginRight: theme.spacing(1) }}>/</div>
  );

  return (
    <div
      id="page-breadcrumb"
      data-testid="navigation"
      style={{ marginBottom: noMargin ? undefined : theme.spacing(2), display: 'flex' }}
    >
      {elements.map((element, index) => {
        if (element.current) {
          return (
            <span key={element.label} style={{ display: 'flex', alignItems: 'center' }}>
              <Typography
                color="text.primary"
              >
                {truncate(element.label, 30, false)}
              </Typography>
              <SplitDiv show={index === elements.length - 1} />
              {isSensitive && <DangerZoneChip />}
            </span>
          );
        }
        if (!element.link) {
          return (
            <Fragment key={element.label}>
              <Typography color="common.lightGrey">{truncate(element.label, 30, false)}</Typography>
              <SplitDiv show={index === elements.length - 1} />
            </Fragment>
          );
        }
        return (
          <Fragment key={element.label}>
            <Link to={element.link}>{truncate(element.label, 30, false)}</Link>
            <SplitDiv show={index === elements.length - 1} />
          </Fragment>
        );
      })}
    </div>
  );
};

export default Breadcrumbs;
