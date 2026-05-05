import ApexCharts from 'apexcharts';
import { CSSProperties, FunctionComponent, ReactNode } from 'react';
import Card, { CardProps } from '../common/card/Card';
import Label from '../common/label/Label';
import ChartExportPopover from '../../private/components/common/charts/ChartExportPopover';
import { ErrorBoundary } from '@components/Error';
import WidgetNoData from './WidgetNoData';

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
            >
              <ErrorBoundary resNotFoundDisplay={<WidgetNoData />}>
                {children}
              </ErrorBoundary>
            </Card>
          )
        : (
            <>
              {title && <Label>{title}</Label>}
              <ErrorBoundary resNotFoundDisplay={<WidgetNoData />}>
                {children}
              </ErrorBoundary>
            </>
          )
      }
    </div>
  );
};

export default WidgetContainer;
