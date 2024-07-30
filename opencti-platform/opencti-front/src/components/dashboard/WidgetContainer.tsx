import Typography from '@mui/material/Typography';
import Paper from '@mui/material/Paper';
import React, { CSSProperties, forwardRef, ReactNode } from 'react';
import makeStyles from '@mui/styles/makeStyles';

// Deprecated - https://mui.com/system/styles/basics/
// Do not use it for new code.
const useStyles = makeStyles({
  paper: {
    minHeight: 110,
    height: '100%',
    margin: '4px 0 0 0',
    padding: '0 0 10px 0',
    borderRadius: 4,
  },
});

interface WidgetContainerProps {
  children: ReactNode
  height?: CSSProperties['height']
  title?: string
  variant: string
  withoutTitle?: boolean
}

const WidgetContainer = forwardRef<HTMLDivElement, WidgetContainerProps>(({
  children,
  height,
  title,
  variant,
  withoutTitle = false,
}, ref) => {
  const classes = useStyles();

  return (
    <div ref={ref} style={{ height: height || '100%' }}>
      {!withoutTitle && (
        <Typography
          variant={variant === 'inEntity' ? 'h3' : 'h4'}
          gutterBottom={true}
          style={{
            margin: variant !== 'inLine' ? '0 0 10px 0' : '-10px 0 10px -7px',
            whiteSpace: 'nowrap',
            overflow: 'hidden',
            textOverflow: 'ellipsis',
          }}
        >
          {title}
        </Typography>
      )}
      {variant !== 'inLine' && variant !== 'inEntity' ? (
        <Paper classes={{ root: classes.paper }} variant="outlined">
          {children}
        </Paper>
      ) : (
        children
      )}
    </div>
  );
});

WidgetContainer.displayName = 'WidgetContainer';

export default WidgetContainer;
