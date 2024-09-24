import React, { FunctionComponent } from 'react';
import { Link } from 'react-router-dom';
import Typography from '@mui/material/Typography';
import { useTheme } from '@mui/styles';
import { truncate } from '../utils/String';
import type { Theme } from './Theme';

interface element {
  label: string;
  link?: string;
  current?: boolean;
}

interface BreadcrumbsProps {
  elements: element[],
}

const Breadcrumbs: FunctionComponent<BreadcrumbsProps> = ({ elements }) => {
  const theme = useTheme<Theme>();

  const SplitDiv = ({ show = true }) => (
    <div style={{ display: show ? 'none' : 'unset', marginLeft: theme.spacing(1), marginRight: theme.spacing(1) }}>/</div>
  );

  return (
    <div data-testid="navigation" style={{ marginBottom: theme.spacing(2), display: 'flex' }}>
      {elements.map((element, index) => {
        if (element.current) {
          return (
            <>
              <Typography key={element.label} color="text.primary">{truncate(element.label, 30, false)}</Typography>
              <SplitDiv show={index === elements.length - 1} />
            </>
          );
        }
        if (!element.link) {
          return (
            <>
              <Typography key={element.label} color="common.lightGrey">{truncate(element.label, 30, false)}</Typography>
              <SplitDiv show={index === elements.length - 1} />
            </>
          );
        }
        return (
          <>
            <Link key={element.label} to={element.link}>{truncate(element.label, 30, false)}</Link>
            <SplitDiv show={index === elements.length - 1} />
          </>
        );
      })}
    </div>
  );
};

export default Breadcrumbs;
