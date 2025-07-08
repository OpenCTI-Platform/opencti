import Typography from '@mui/material/Typography';
import Paper from '@mui/material/Paper';
import React, { CSSProperties, FunctionComponent, ReactNode } from 'react';

interface WidgetContainerProps {
  children: ReactNode
  height?: CSSProperties['height']
  title?: string
  variant?: string
  withoutTitle?: boolean
}

const WidgetContainer: FunctionComponent<WidgetContainerProps> = ({
  children,
  height,
  title,
  variant,
  withoutTitle = false,
}) => {
  return (
    <div style={{ height: height || '100%' }}>
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
        <Paper
          style={{
            minHeight: 110,
            height: '100%',
            margin: '4px 0 0 0',
            borderRadius: 4,
          }}
          variant="outlined"
        >
          {children}
        </Paper>
      ) : (
        children
      )}
    </div>
  );
};

export default WidgetContainer;
