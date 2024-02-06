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
import { resolveLink } from '../../utils/Entity';
import { useFormatter } from '../i18n';

interface WidgetTimelineProps {
  data: any[]
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
        {data.map((stixCoreObjectEdge) => {
          const stixCoreObject = stixCoreObjectEdge.node;
          const link = `${resolveLink(stixCoreObject.entity_type)}/${stixCoreObject.id}`;
          return (
            <TimelineItem key={stixCoreObject.id}>
              <TimelineOppositeContent
                sx={{ paddingTop: '18px' }}
                color="text.secondary"
              >
                {fldt(stixCoreObject.created)}
              </TimelineOppositeContent>
              <TimelineSeparator>
                <Link to={link}>
                  <TimelineDot
                    sx={{ borderColor: itemColor(stixCoreObject.entity_type) }}
                    variant="outlined"
                    className="noDrag"
                  >
                    <ItemIcon type={stixCoreObject.entity_type} />
                  </TimelineDot>
                </Link>
                <TimelineConnector />
              </TimelineSeparator>
              <TimelineContent>
                <Paper variant="outlined" sx={{ padding: '15px' }} className="noDrag">
                  <Typography variant="h2">
                    {defaultValue(stixCoreObject)}
                  </Typography>
                  <div style={{ marginTop: -5, color: '#a8a8a8' }}>
                    <MarkdownDisplay
                      content={stixCoreObject.description}
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
