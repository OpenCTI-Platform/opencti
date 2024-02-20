import React, { FunctionComponent } from 'react';
import MUIBreadcrumbs from '@mui/material/Breadcrumbs';
import { Link } from 'react-router-dom';
import Typography from '@mui/material/Typography';
import makeStyles from '@mui/styles/makeStyles';
import { truncate } from '../utils/String';

interface element {
  label: string;
  link?: string;
  current?: boolean;
}

interface BreadcrumbsProps {
  variant: 'standard' | 'list' | 'object',
  elements: element[],
}

const useStyles = makeStyles(() => ({
  breadcrumbsList: {
    marginTop: -5,
    marginBottom: 25,
  },
  breadcrumbsObject: {
    marginTop: -5,
    marginBottom: 15,
  },
  breadcrumbsStandard: {
    marginTop: -5,
  },
}));

const Breadcrumbs: FunctionComponent<BreadcrumbsProps> = ({ elements, variant }) => {
  const classes = useStyles();
  let className = classes.breadcrumbsStandard;
  if (variant === 'list') {
    className = classes.breadcrumbsList;
  } else if (variant === 'object') {
    className = classes.breadcrumbsObject;
  }
  return (
    <MUIBreadcrumbs classes={{ root: className }}>
      {elements.map((element) => {
        if (element.current) {
          return (
            <Typography key={element.label} color="text.primary">{truncate(element.label, 26)}</Typography>
          );
        }
        if (!element.link) {
          return (
            <Typography key={element.label} color="inherit">{truncate(element.label, 26)}</Typography>
          );
        }
        return (
          <Link key={element.label} to={element.link}>{truncate(element.label, 26)}</Link>
        );
      })}
    </MUIBreadcrumbs>
  );
};

export default Breadcrumbs;
