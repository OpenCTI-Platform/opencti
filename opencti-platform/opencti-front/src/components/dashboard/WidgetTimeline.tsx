import Timeline from '@mui/lab/Timeline';
import TimelineItem from '@mui/lab/TimelineItem';
import TimelineOppositeContent from '@mui/lab/TimelineOppositeContent';
import TimelineSeparator from '@mui/lab/TimelineSeparator';
import { Link } from 'react-router-dom';
import TimelineDot from '@mui/lab/TimelineDot';
import TimelineConnector from '@mui/lab/TimelineConnector';
import TimelineContent from '@mui/lab/TimelineContent';
import Paper from '@mui/material/Paper';
import Typography from '@mui/material/Typography';
import React from 'react';
import { defaultValue } from '../../utils/Graph';
import MarkdownDisplay from '../MarkdownDisplay';
import ItemIcon from '../ItemIcon';
import { itemColor } from '../../utils/Colors';
import { useFormatter } from '../i18n';

interface WidgetTimelineProps {
  data: { value: any, link?: string }[]
}

const WidgetTimeline = ({ data }: WidgetTimelineProps) => {
  const { fldt } = useFormatter();

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
        {data.map(({ value, link }) => {
          return (
            <TimelineItem key={value.id}>
              <TimelineOppositeContent
                sx={{ paddingTop: '18px' }}
                color="text.secondary"
              >
                {fldt(value.created)}
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
                <Paper variant="outlined" sx={{ padding: '15px' }} className="noDrag">
                  <Typography variant="h2">
                    {defaultValue(value)}
                  </Typography>
                  <div style={{ marginTop: -5, color: '#a8a8a8' }}>
                    <MarkdownDisplay
                      content={value.description}
                      limit={150}
                    />
                  </div>
                </Paper>
              </TimelineContent>
            </TimelineItem>
          );
        })}
      </Timeline>
    </div>
  );
};

export default WidgetTimeline;
