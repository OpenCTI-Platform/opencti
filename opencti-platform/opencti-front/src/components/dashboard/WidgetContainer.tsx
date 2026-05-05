import ApexCharts from 'apexcharts';
import { CSSProperties, FunctionComponent, ReactNode } from 'react';
import Card, { CardProps } from '../common/card/Card';
import Label from '../common/label/Label';
import ChartExportPopover from '../../private/components/common/charts/ChartExportPopover';
import { ErrorBoundary } from '@components/Error';
import WidgetNoData from './WidgetNoData';
import Stack from '@mui/material/Stack';
import { useTheme } from '@mui/styles';
import type { Theme } from '../../components/Theme';
import { hexToRGB } from '../../utils/Colors';
import { useFormatter } from '../../components/i18n';
import Tag from '@common/tag/Tag';

interface WidgetContainerProps {
  children: ReactNode;
  height?: CSSProperties['height'];
  title?: string;
  variant?: string;
  padding?: CardProps['padding'];
  chart?: ApexCharts;
  action?: ReactNode;
  showPreviewTag?: boolean;
}

const WidgetContainer: FunctionComponent<WidgetContainerProps> = ({
  children,
  height,
  title,
  variant,
  padding,
  chart,
  action,
  showPreviewTag,
}) => {
  const theme = useTheme<Theme>();
  const { t_i18n } = useFormatter();
  const previewColor = theme.palette.designSystem.tertiary.orange['400'];
  return (
    <div style={{ height: height || '100%' }}>
      {variant !== 'inLine' && variant !== 'inEntity'
        ? (
            <Card
              title={showPreviewTag ? (
                <Stack direction="row" alignItems="center" gap={1}>
                  {title}
                  <Tag
                    label={t_i18n('Preview data')}
                    size="small"
                    sx={{
                      backgroundColor: hexToRGB(previewColor, 0.1),
                      color: previewColor,
                      border: `1px solid ${previewColor}`,
                      fontWeight: 700,
                      fontSize: '0.65rem',
                    }}
                  />
                </Stack>
              ) : title}
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
