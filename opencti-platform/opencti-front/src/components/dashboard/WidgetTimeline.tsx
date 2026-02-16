import Timeline from '@mui/lab/Timeline';
import TimelineItem from '@mui/lab/TimelineItem';
import TimelineOppositeContent from '@mui/lab/TimelineOppositeContent';
import TimelineSeparator from '@mui/lab/TimelineSeparator';
import { Link } from 'react-router-dom';
import TimelineDot from '@mui/lab/TimelineDot';
import TimelineConnector from '@mui/lab/TimelineConnector';
import TimelineContent from '@mui/lab/TimelineContent';
import Typography from '@mui/material/Typography';
import { getSecondaryRepresentative, getMainRepresentative } from '../../utils/defaultRepresentatives';
import MarkdownDisplay from '../MarkdownDisplay';
import ItemIcon from '../ItemIcon';
import { itemColor } from '../../utils/Colors';
import { useFormatter } from '../i18n';
import FieldOrEmpty from '../FieldOrEmpty';
import Card from '../common/card/Card';
import { useTheme } from '@mui/styles';
import { Theme } from '../Theme';

interface WidgetTimelineProps {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  data: { value: any; link?: string }[];
  dateAttribute?: string;
}

const WidgetTimeline = ({ data, dateAttribute = 'created_at' }: WidgetTimelineProps) => {
  const { fldt } = useFormatter();
  const theme = useTheme<Theme>();

  return (
    <div
      id="container"
      style={{
        width: '100%',
        height: '100%',
        overflow: 'auto',
      }}
    >
      <Timeline position="alternate">
        {data.map(({ value, link }, index) => {
          return (
            <TimelineItem key={`${value.id}-${index}`}>
              <TimelineOppositeContent
                sx={{ paddingTop: '18px' }}
                color="text.secondary"
              >
                <FieldOrEmpty source={value[dateAttribute]}>
                  {fldt(value[dateAttribute])}
                </FieldOrEmpty>
              </TimelineOppositeContent>
              <TimelineSeparator>
                {link ? (
                  <Link to={link}>
                    <TimelineDot
                      sx={{ borderColor: itemColor(value.entity_type) }}
                      variant="outlined"
                      className="noDrag"
                    >
                      <ItemIcon type={value.entity_type} />
                    </TimelineDot>
                  </Link>
                ) : (
                  <TimelineDot
                    sx={{ borderColor: itemColor(value.entity_type) }}
                    variant="outlined"
                    className="noDrag"
                  >
                    <ItemIcon type={value.entity_type} />
                  </TimelineDot>
                )}
                <TimelineConnector />
              </TimelineSeparator>
              <TimelineContent>
                <Card sx={{ background: theme.palette.designSystem.background.main }}>
                  <Typography variant="h2">
                    {getMainRepresentative(value)}
                  </Typography>
                  <div style={{ marginTop: -5, color: theme.palette.text.secondary }}>
                    <MarkdownDisplay
                      content={getSecondaryRepresentative(value)}
                      limit={150}
                    />
                  </div>
                </Card>
              </TimelineContent>
            </TimelineItem>
          );
        })}
      </Timeline>
    </div>
  );
};

export default WidgetTimeline;
