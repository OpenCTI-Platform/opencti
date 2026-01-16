import { CSSProperties, FunctionComponent, ReactNode } from 'react';
import Card, { CardProps } from '../common/card/Card';
import Label from '../common/label/Label';

interface WidgetContainerProps {
  children: ReactNode;
  height?: CSSProperties['height'];
  title?: string;
  variant?: string;
  padding?: CardProps['padding'];
}

const WidgetContainer: FunctionComponent<WidgetContainerProps> = ({
  children,
  height,
  title,
  variant,
  padding,
}) => {
  return (
    <div style={{ height: height || '100%' }}>
      {variant !== 'inLine' && variant !== 'inEntity'
        ? <Card title={title} padding={padding}>{children}</Card>
        : (
            <>
              {title && <Label>{title}</Label>}
              {children}
            </>
          )
      }
    </div>
  );
};

export default WidgetContainer;
