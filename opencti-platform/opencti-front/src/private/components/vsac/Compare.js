/* refactor */
/* eslint-disable */
import React, { useState } from 'react';
import { Redirect } from 'react-router-dom';
import FiberManualRecordIcon from '@material-ui/icons/FiberManualRecord';
import Grid from '@material-ui/core/Grid';
import Paper from '@material-ui/core/Paper';
import List from '@material-ui/core/List';
import ListItem from '@material-ui/core/ListItem';
import ListItemText from '@material-ui/core/ListItemText';
import ListItemSecondaryAction from '@material-ui/core/ListItemSecondaryAction';
import moment from 'moment';
import {
  ScatterChart,
  Scatter,
  XAxis,
  YAxis,
  ReferenceLine,
  ResponsiveContainer,
  Tooltip,
} from 'recharts';
import Chip from '@material-ui/core/Chip';

const Compare = (props) => {
  const [getAnalyses] = useState(props.location.state?.analyses);
  const [getScatterPlotData] = useState(props.location.state?.scatterPlotData);

  const scatter = [];

  if(props.location.state == undefined) return <Redirect to="/activities/vulnerability_assessment/scans" />;

  const CustomTooltip = ({ active, payload, label }) => {
    if (active && payload && payload.length) {
      return (
        <div
          className="custom-tooltip"
          style={{
            backgroundColor: 'rgba(255, 255, 255, 0.1)',
            fontSize: 12,
            borderRadius: 10,
            border: 1,
            padding: 10,
          }}>
          <p className="label" style={{ paddingBottom: 5 }}>{payload[0].payload.cwe_name}</p>
          <p className="weakness" style={{ paddingBottom: 5 }}>{`Weakness Score: ${payload[0].payload.score}`}</p>
          <p className="host" style={{ paddingBottom: 5 }}>{`Hosts with Weakness: ${payload[0].payload.host_count_total} (${payload[0].payload.x}%)`}</p>
        </div>
      );
    }
    return null;
  };

  return (
    <Grid container={true} spacing={3}>
      <Grid item={true} xs={4}>
        <Paper elevation={2} style={{ height: '920px', marginBottom: 20, overflowY: 'scroll' }}>
          <List>
            { getAnalyses.map((analysis, i) => {
              const hex = Math.floor(Math.random() * 16777215).toString(16);
              const fillColor = `#${hex}`;
              scatter.push({
                name: analysis.scan.scan_name,
                data: getScatterPlotData[analysis.id],
                fill: fillColor,
              });

              return (
                  <ListItem
                    key={i}
                    button>
                    <ListItemText
                      id={analysis.scan.id}
                      primary={analysis.scan.scan_name}
                      secondary={
                        <React.Fragment>
                          <div style={{ marginBottom: 10 }}>
                            {moment(analysis.completed_date).fromNow()}
                          </div>
                          {analysis.weakness_range && (
                            <Chip
                              size="small"
                              style={{ margin: 3 }}
                              label={`Top  ${analysis.weakness_range}`}
                            />
                          )}
                          {analysis.vulnerability_range && (
                            <Chip
                              size="small"
                              style={{ margin: 3 }}
                              label={`Previous ${analysis.vulnerability_range} Years`}
                            />
                          )}
                          {analysis.vignette_name && (
                            <Chip
                              size="small"
                              style={{ margin: 3 }}
                              label={analysis.vignette_name}
                            />
                          )}
                        </React.Fragment>
                      }
                    />
                    <ListItemSecondaryAction>
                      <FiberManualRecordIcon style={{ color: fillColor }} />
                    </ListItemSecondaryAction>
                  </ListItem>
              );
            })}
          </List>
        </Paper>
      </Grid>
      <Grid item={true} xs={8}>
        <Paper elevation={2} style={{ marginBottom: 20, padding: 5 }}>
          <ResponsiveContainer width="100%" aspect={1}>
            <ScatterChart
              width={500}
              height={500}
              margin={{
                top: 0,
                right: 0,
                bottom: 20,
                left: 0,
              }}
            >
              <XAxis
                type="number"
                dataKey="x"
                label={{
                  value: '% of Hosts with Weakness',
                  fill: 'white',
                }}
                domain={[-200, 200]}
                tick={false}
              />
              <YAxis
                type="number"
                dataKey="y"
                label={{
                  value: 'Weakness Score',
                  angle: -90,
                  fill: 'white',
                  textAnchor: 'middle',
                }}
                domain={[-200, 200]}
                tick={false}
              />
              <ReferenceLine x={0} stroke="white" />
              <ReferenceLine y={0} stroke="white" />
              <Tooltip
                content={<CustomTooltip />}
                cursor={false}
              />
              {scatter.map((plot, i) => (
                 <Scatter key={i} name={plot.name} data={plot.data} fill={plot.fill} />
              ))}
            </ScatterChart>
          </ResponsiveContainer>
        </Paper>
      </Grid>
    </Grid>
  );
};

export default Compare;
