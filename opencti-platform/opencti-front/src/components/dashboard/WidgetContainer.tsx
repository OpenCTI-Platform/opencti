import ApexCharts from 'apexcharts';
import { CSSProperties, FunctionComponent, ReactNode } from 'react';
import Card, { CardProps } from '../common/card/Card';
import Label from '../common/label/Label';
import ChartExportPopover from '../../private/components/common/charts/ChartExportPopover';

interface WidgetContainerProps {
  children: ReactNode;
  height?: CSSProperties['height'];
  title?: string;
  variant?: string;
  padding?: CardProps['padding'];
  chart?: ApexCharts;
  action?: ReactNode;
}

const WidgetContainer: FunctionComponent<WidgetContainerProps> = ({
  children,
  height,
  title,
  variant,
  padding,
  chart,
  action,
}) => {
  return (
    <div style={{ height: height || '100%' }}>
      {variant !== 'inLine' && variant !== 'inEntity'
        ? (
            <Card
              title={title}
              padding={padding}
              action={(
                <div>
                  {chart && <ChartExportPopover chart={chart} />}
                  {action}
                </div>
              )}
            >{children}
            </Card>
          )
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
