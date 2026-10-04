import Chart from '@components/common/charts/Chart';
import { useTheme } from '@mui/styles';
import type { Theme } from '../../../../components/Theme';
import { useFormatter } from '../../../../components/i18n';
import useCurationLabels from './curationUtils';

interface KnowledgeHealthScoreProps {
  score: number;
  height?: number;
}

const KnowledgeHealthScore = ({ score, height = 220 }: KnowledgeHealthScoreProps) => {
  const theme = useTheme<Theme>();
  const { t_i18n } = useFormatter();
  const { healthColor } = useCurationLabels();
  return (
    <div role="img" aria-label={t_i18n('Knowledge health score: {score} of 100', { values: { score } })} data-testid="knowledge-health-score">
      {/* The radial bar does not redraw a new value in place: a new score mounts a new chart. */}
      <Chart
        key={score}
        options={{
          chart: { type: 'radialBar', background: 'transparent', sparkline: { enabled: true } },
          plotOptions: {
            radialBar: {
              startAngle: -120,
              endAngle: 120,
              hollow: { size: '62%' },
              track: { show: true, background: theme.palette.background.accent },
              dataLabels: {
                name: { show: true, offsetY: 22, color: theme.palette.text?.secondary, fontSize: '12px' },
                value: { color: theme.palette.text?.primary, offsetY: -12, fontSize: '32px', formatter: (value: number) => `${Math.round(value)}` },
              },
            },
          },
          labels: [t_i18n('out of 100')],
          colors: [healthColor(score)],
          stroke: { lineCap: 'round' },
        }}
        series={[Math.max(0, Math.min(100, score))]}
        type="radialBar"
        width="100%"
        height={height}
      />
    </div>
  );
};

export default KnowledgeHealthScore;
