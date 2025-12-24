import { CSSProperties, FunctionComponent, ReactNode } from 'react';
import Card from '../common/card/Card';

interface WidgetContainerProps {
  children: ReactNode;
  height?: CSSProperties['height'];
  title?: string;
  variant?: string;
  noPadding?: boolean;
}

const WidgetContainer: FunctionComponent<WidgetContainerProps> = ({
  children,
  height,
  title,
  variant,
  noPadding,
}) => {
  return (
    <div style={{ height: height || '100%' }}>
      {variant !== 'inLine' && variant !== 'inEntity'
        ? <Card title={title} noPadding={noPadding}>{children}</Card>
        : children
      }
    </div>
  );
};

export default WidgetContainer;
