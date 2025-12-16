import React, { useMemo } from 'react';
import { useFormatter } from '../../../../../components/i18n';
import Breadcrumbs from '../../../../../components/Breadcrumbs';
import useConnectedDocumentModifier from '../../../../../utils/hooks/useConnectedDocumentModifier';
import {
  Box,
  Card,
  CardContent,
  Grid,
  Typography,
  LinearProgress,
  Avatar,
  List,
  ListItem,
  ListItemAvatar,
  ListItemText,
  Divider,
  Button,
  IconButton,
  TextField,
  Paper,
} from '@mui/material';
import {
  SendOutlined,
  WebOutlined,
  MessageOutlined,
  Menu,
  Edit,
  GridView,
  ArrowDropDown,
  VideoCall,
  Add,
  MoreVert,
  ThumbUp,
  Favorite,
  SentimentSatisfied,
} from '@mui/icons-material';
import { Github } from 'mdi-material-ui';
import { ArrowUpward, ArrowDownward } from '@mui/icons-material';
import { useTheme } from '@mui/styles';
import type { ApexOptions } from 'apexcharts';
import Chart from '@components/common/charts/Chart';
import { lineChartOptions, donutChartOptions } from '../../../../../utils/Charts';
import type { Theme } from '../../../../../components/Theme';

interface StatCardProps {
  title: string;
  value: number;
  change: number;
  icon: React.ReactNode;
  isPositive: boolean;
}

const StatCard: React.FC<StatCardProps> = ({ title, value, change, icon, isPositive }) => {
  const changeColor = isPositive ? '#d32f2f' : '#2e7d32';
  const changeBgColor = isPositive ? '#ffebee' : '#e8f5e9';

  return (
    <Card
      variant="outlined"
      sx={{
        height: '100%',
        position: 'relative',
        backgroundColor: '#fafafa',
      }}
    >
      <CardContent sx={{ padding: 2.5 }}>
        <Box sx={{ display: 'flex', alignItems: 'flex-start' }}>
          {/* Icon on the left */}
          <Box
            sx={{
              color: '#757575',
              marginRight: 2,
              display: 'flex',
              alignItems: 'center',
              flexShrink: 0,
            }}
          >
            <Box sx={{ fontSize: '2.5rem' }}>
              {icon}
            </Box>
          </Box>
          {/* Content on the right - two rows */}
          <Box sx={{ flex: 1, display: 'flex', flexDirection: 'column' }}>
            {/* First row: Title */}
            <Typography
              variant="body2"
              sx={{
                color: '#424242',
                fontWeight: 500,
                fontSize: '0.875rem',
                marginBottom: 1.5,
              }}
            >
              {title}
            </Typography>
            {/* Second row: Value and change percentage */}
            <Box sx={{ display: 'flex', alignItems: 'center', gap: 1.5 }}>
              <Typography
                variant="h4"
                sx={{
                  fontWeight: 600,
                  color: '#212121',
                  fontSize: '1.2rem',
                }}
              >
                {value.toLocaleString()}
              </Typography>
              <Box
                sx={{
                  display: 'inline-flex',
                  alignItems: 'center',
                  padding: '4px 8px',
                  borderRadius: '12px',
                  backgroundColor: changeBgColor,
                  color: changeColor,
                  fontSize: '0.75rem',
                  fontWeight: 500,
                }}
              >
                {Math.abs(change)}%
                {isPositive ? (
                  <ArrowUpward sx={{ fontSize: '0.875rem', marginLeft: 0.5 }} />
                ) : (
                  <ArrowDownward sx={{ fontSize: '0.875rem', marginLeft: 0.5 }} />
                )}
              </Box>
            </Box>
          </Box>
        </Box>
      </CardContent>
    </Card>
  );
};

interface DonutChartProps {
  data: { label: string; value: number; color: string }[];
  total: number;
}

const DonutChart: React.FC<DonutChartProps> = ({ data, total }) => {
  const theme = useTheme<Theme>();

  const chartData = useMemo(() => data.map((item) => item.value), [data]);
  const labels = useMemo(() => data.map((item) => item.label), [data]);
  const colors = useMemo(() => data.map((item) => item.color), [data]);

  const options: ApexOptions = useMemo(() => {
    const baseOptions = donutChartOptions(
      theme,
      labels,
      'right',
      false,
      colors,
      true, // displayLegend: true - legend چارت را فعال می‌کنیم
      false, // displayLabels: false - درصد‌ها را از روی نمودار برمی‌داریم
      true,
      true,
      70,
      false,
    ) as ApexOptions;

    // محاسبه درصد برای هر آیتم
    const percentages = chartData.map((value) => ((value / total) * 100).toFixed(1));

    return {
      ...baseOptions,
      labels: labels, // اضافه کردن labels برای نمایش در legend
      chart: {
        ...baseOptions.chart,
        events: {
          ...baseOptions.chart?.events,
          mounted: (chartContext: any) => {
            // اطمینان از نمایش همیشگی labels
            if (chartContext && chartContext.w) {
              const apexChart = chartContext.w.globals;
              if (apexChart) {
                // Force update برای نمایش labels
                setTimeout(() => {
                  chartContext.updateSeries(chartData, true);
                }, 100);
              }
            }
          },
        },
      },
      legend: {
        ...baseOptions.legend,
        position: 'right',
        horizontalAlign: 'center',
        floating: false,
        fontSize: '12px',
        fontFamily: '"IBM Plex Sans", sans-serif',
        fontColor: '#212121',
        labels: {
          colors: '#212121',
        },
        itemMargin: {
          horizontal: 10,
          vertical: 5,
        },
        formatter: (seriesName: string, opts: { seriesIndex: number }) => {
          const percentage = percentages[opts.seriesIndex];
          return `${seriesName} ${percentage}%`;
        },
      },
      dataLabels: {
        ...baseOptions.dataLabels,
        enabled: false, // درصد‌ها را از روی نمودار برمی‌داریم
      },
      tooltip: {
        ...baseOptions.tooltip,
        enabled: true,
      },
      plotOptions: {
        ...baseOptions.plotOptions,
        pie: {
          ...baseOptions.plotOptions?.pie,
          donut: {
            ...baseOptions.plotOptions?.pie?.donut,
            labels: {
              show: true,
              name: {
                show: true,
                fontSize: '14px',
                fontFamily: '"IBM Plex Sans", sans-serif',
                fontWeight: 400,
                color: theme.palette.text?.secondary || '#757575',
                offsetY: -10,
                formatter: () => 'Total',
              },
              value: {
                show: true,
                fontSize: '24px',
                fontFamily: '"IBM Plex Sans", sans-serif',
                fontWeight: 600,
                color: theme.palette.text?.primary || '#212121',
                offsetY: 10,
                formatter: () => total.toLocaleString(),
              },
              total: {
                show: true,
                showAlways: true,
                label: 'Total',
                fontSize: '14px',
                fontFamily: '"IBM Plex Sans", sans-serif',
                fontWeight: 400,
                color: theme.palette.text?.secondary || '#757575',
                formatter: () => total.toLocaleString(),
              },
            },
          },
        },
      },
    };
  }, [theme, labels, colors, total, chartData]);

  return (
    <Box sx={{ height: 300 }}>
      <Chart
        options={options}
        series={chartData}
        type="donut"
        width="100%"
        height="100%"
      />
    </Box>
  );
};

interface ProgressListProps {
  items: { name: string; value: number }[];
}

const ProgressList: React.FC<ProgressListProps> = ({ items }) => {
  const maxValue = Math.max(...items.map((item) => item.value));

  return (
    <Box sx={{ display: 'flex', flexDirection: 'column', gap: 2 }}>
      {items.map((item, index) => (
        <Box key={index}>
          <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 0.5 }}>
            <Typography variant="body2" sx={{ fontSize: '0.875rem', color: '#424242' }}>
              {item.name}
            </Typography>
            <Typography variant="body2" sx={{ fontSize: '0.875rem', fontWeight: 600, color: '#212121' }}>
              {item.value}
            </Typography>
          </Box>
          <LinearProgress
            variant="determinate"
            value={(item.value / maxValue) * 100}
            sx={{
              height: 8,
              borderRadius: 4,
              backgroundColor: '#e0e0e0',
              '& .MuiLinearProgress-bar': {
                borderRadius: 4,
                backgroundColor: '#1976d2',
              },
            }}
          />
        </Box>
      ))}
    </Box>
  );
};

const RessaDWM = () => {
  const { t_i18n } = useFormatter();

  const { setTitle } = useConnectedDocumentModifier();
  setTitle(t_i18n('Ressa DWM'));

  const stats = [
    {
      title: 'All New Leaks',
      value: 129,
      change: 30,
      icon: <SendOutlined />,
      isPositive: true,
    },
    {
      title: 'Dark Web',
      value: 43,
      change: 19,
      icon: <Github />,
      isPositive: false,
    },
    {
      title: 'Web',
      value: 26,
      change: 63,
      icon: <WebOutlined />,
      isPositive: true,
    },
    {
      title: 'Telegram',
      value: 32,
      change: 39,
      icon: <MessageOutlined />,
      isPositive: true,
    },
  ];

  return (
    <>
      <Breadcrumbs
        elements={[
          { label: t_i18n('Dashboards') },
          { label: t_i18n('Ressa DWM'), current: true },
        ]}
      />
      <Box sx={{ padding: 0 }}>
        <Grid container spacing={3} sx={{ marginBottom: 3 }}>
          {stats.map((stat) => (
            <Grid item xs={12} sm={6} md={3} key={stat.title}>
              <StatCard
                title={stat.title}
                value={stat.value}
                change={stat.change}
                icon={stat.icon}
                isPositive={stat.isPositive}
              />
            </Grid>
          ))}
        </Grid>

        {/* Three panels below */}
        <Grid container spacing={3}>
          {/* Monitored Sources Panel */}
          <Grid item xs={12} md={4}>
            <Card variant="outlined" sx={{ height: '100%', backgroundColor: '#fafafa' }}>
              <CardContent>
                <Typography
                  variant="h6"
                  sx={{
                    fontWeight: 600,
                    marginBottom: 2,
                    color: '#212121',
                    fontSize: '1rem',
                  }}
                >
                  Monitored Sources
                </Typography>
                <DonutChart
                  data={[
                    { label: 'Web', value: 25000, color: '#1565c0' },
                    { label: 'Forums', value: 12000, color: '#64b5f6' },
                    { label: 'Telegram', value: 15000, color: '#42a5f5' },
                    { label: 'Dark Web', value: 18000, color: '#0d47a1' },
                    { label: 'Social Media', value: 10000, color: '#42a5f5' },
                    { label: 'Deep Web', value: 8000, color: '#90caf9' },
                    { label: 'Chat Apps', value: 7000, color: '#42a5f5' },
                    { label: 'Email', value: 5000, color: '#0d47a1' },
                    { label: 'Gaming Platforms', value: 3000, color: '#42a5f5' },
                    { label: 'File Sharing', value: 1670, color: '#90caf9' },
                  ]}
                  total={98670}
                />
              </CardContent>
            </Card>
          </Grid>

          {/* Top Leaks Panel */}
          <Grid item xs={12} md={4}>
            <Card variant="outlined" sx={{ height: '100%', backgroundColor: '#fafafa' }}>
              <CardContent>
                <Typography
                  variant="h6"
                  sx={{
                    fontWeight: 600,
                    marginBottom: 2,
                    color: '#212121',
                    fontSize: '1rem',
                  }}
                >
                  Top Leaks
                </Typography>
                <ProgressList
                  items={[
                    { name: 'IRLeaks', value: 150 },
                    { name: 'bakhtak', value: 120 },
                    { name: 'We Red Evils Original', value: 100 },
                    { name: 'OnHex', value: 60 },
                    { name: 'CVE Notify', value: 35 },
                  ]}
                />
              </CardContent>
            </Card>
          </Grid>

          {/* Top Damageable Panel */}
          <Grid item xs={12} md={4}>
            <Card variant="outlined" sx={{ height: '100%', backgroundColor: '#fafafa' }}>
              <CardContent>
                <Typography
                  variant="h6"
                  sx={{
                    fontWeight: 600,
                    marginBottom: 2,
                    color: '#212121',
                    fontSize: '1rem',
                  }}
                >
                  Top Damageable
                </Typography>
                <ProgressList
                  items={[
                    { name: 'Tapsi.ir', value: 109 },
                    { name: 'Snapp.ir', value: 85 },
                    { name: 'Varzesh3.com', value: 78 },
                    { name: 'Irancell.com', value: 66 },
                    { name: 'mci.ir', value: 47 },
                  ]}
                />
              </CardContent>
            </Card>
          </Grid>
        </Grid>

        {/* Two trend charts */}
        <Grid container spacing={3} sx={{ marginTop: 0 }}>
          {/* Vulnerability Trends Chart */}
          <Grid item xs={12} md={6}>
            <Card variant="outlined" sx={{ height: '100%', backgroundColor: '#fafafa' }}>
              <CardContent>
                <Typography
                  variant="h6"
                  sx={{
                    fontWeight: 600,
                    marginBottom: 2,
                    color: '#212121',
                    fontSize: '1rem',
                  }}
                >
                  Vulnerability Trends Over Time (by Source)
                </Typography>
                <TrendChart
                  series={[
                    {
                      name: 'Dark Web',
                      data: [220, 240, 280, 320, 350, 380, 360, 400, 450, 500, 550, 580],
                      color: '#64b5f6',
                    },
                    {
                      name: 'Telegram',
                      data: [450, 470, 480, 490, 500, 510, 520, 530, 540, 550, 560, 580],
                      color: '#42a5f5',
                    },
                    {
                      name: 'Web',
                      data: [650, 680, 700, 720, 750, 780, 760, 800, 820, 840, 860, 880],
                      color: '#1565c0',
                    },
                  ]}
                />
              </CardContent>
            </Card>
          </Grid>

          {/* Data Leak Trends Chart */}
          <Grid item xs={12} md={6}>
            <Card variant="outlined" sx={{ height: '100%', backgroundColor: '#fafafa' }}>
              <CardContent>
                <Typography
                  variant="h6"
                  sx={{
                    fontWeight: 600,
                    marginBottom: 2,
                    color: '#212121',
                    fontSize: '1rem',
                  }}
                >
                  Data Leak Trends Over Time (by Source)
                </Typography>
                <TrendChart
                  series={[
                    {
                      name: 'Dark Web',
                      data: [220, 240, 280, 320, 350, 380, 360, 400, 450, 500, 550, 580],
                      color: '#64b5f6',
                    },
                    {
                      name: 'Telegram',
                      data: [450, 470, 480, 490, 500, 510, 520, 530, 540, 550, 560, 580],
                      color: '#42a5f5',
                    },
                    {
                      name: 'Web',
                      data: [650, 680, 700, 720, 750, 780, 760, 800, 820, 840, 860, 880],
                      color: '#1565c0',
                    },
                  ]}
                />
              </CardContent>
            </Card>
          </Grid>
        </Grid>

        {/* Chat Section */}
        <Box sx={{ marginTop: 3 }}>
          <ChatInterface />
        </Box>
      </Box>
    </>
  );
};

interface TrendChartProps {
  series: { name: string; data: number[]; color: string }[];
}

const TrendChart: React.FC<TrendChartProps> = ({ series }) => {
  const theme = useTheme<Theme>();

  const months = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'];

  const chartSeries = series.map((s) => ({
    name: s.name,
    data: s.data,
  }));

  const options: ApexOptions = useMemo(() => {
    const baseOptions = lineChartOptions(
      theme,
      false,
      undefined,
      (value: number) => value.toString(),
      undefined,
      false,
      true,
    ) as ApexOptions;

    return {
      ...baseOptions,
      colors: series.map((s) => s.color),
      xaxis: {
        ...baseOptions.xaxis,
        categories: months,
      },
      yaxis: {
        ...baseOptions.yaxis,
        min: 0,
        max: 1000,
        tickAmount: 5,
      },
      legend: {
        ...baseOptions.legend,
        position: 'top',
        horizontalAlign: 'left',
      },
      chart: {
        ...baseOptions.chart,
        toolbar: {
          show: false,
        },
      },
    };
  }, [theme, series, months]);

  return (
    <Box sx={{ height: 300 }}>
      <Chart
        options={options}
        series={chartSeries}
        type="line"
        width="100%"
        height="100%"
      />
    </Box>
  );
};

interface ChatItem {
  id: string;
  name: string;
  avatar: string;
  lastMessage: string;
  time: string;
  isOnline?: boolean;
  isGroup?: boolean;
}

interface ChatMessage {
  id: string;
  sender: string;
  avatar: string;
  message: string;
  time: string;
  isOnline?: boolean;
  reactions?: { type: string; count: number }[];
  attachment?: string;
}

const ChatInterface: React.FC = () => {
  const pinnedChats: ChatItem[] = [
    { id: '1', name: 'Ray Tanaka', avatar: 'RT', lastMessage: 'Hey, how are you?', time: '2:30 PM', isOnline: true },
    { id: '2', name: 'Beth Davies', avatar: 'BD', lastMessage: 'See you tomorrow', time: '1:15 PM', isOnline: true },
    { id: '3', name: 'Kayo Miwa', avatar: 'KM', lastMessage: 'Thanks for the update', time: '12:45 PM', isOnline: true },
    { id: '4', name: 'Will, Kayo, Eric, +2', avatar: 'G', lastMessage: 'Meeting at 3 PM', time: '11:20 AM', isGroup: true },
    { id: '5', name: 'August Bergman', avatar: 'AB', lastMessage: 'Got it, thanks!', time: '10:10 AM', isOnline: true },
  ];

  const recentChats: ChatItem[] = [
    { id: '6', name: 'Amanda Brady', avatar: 'AB', lastMessage: 'Can we schedule a call?', time: '9:30 AM' },
    { id: '7', name: 'Emiliano Ceballos', avatar: 'EC', lastMessage: '😂😂', time: 'Yesterday' },
    { id: '8', name: 'Oscar Krogh', avatar: 'OK', lastMessage: 'Perfect!', time: 'Yesterday' },
    { id: '9', name: 'Daichi Fukuda', avatar: 'DF', lastMessage: 'Working on it...', time: '2 days ago', isOnline: true },
    { id: '10', name: 'Kian Lambert', avatar: 'KL', lastMessage: 'See you later', time: '2 days ago' },
    { id: '11', name: 'Team Design Template', avatar: 'TD', lastMessage: 'New design ready', time: '3 days ago', isGroup: true },
  ];

  const messages: ChatMessage[] = [
    {
      id: '1',
      sender: 'Marie Beaudouin',
      avatar: 'MB',
      message: 'Thank you for always being so positive!',
      time: '2:30 PM',
      isOnline: true,
    },
    {
      id: '2',
      sender: 'System',
      avatar: 'S',
      message: 'W July_Promotion',
      time: '2:25 PM',
      attachment: 'file',
    },
    {
      id: '3',
      sender: 'Daichi Fukuda',
      avatar: 'DF',
      message: 'Cupcake ipsum dolor sit amet muffin sesame snaps caramels. Gingerbread chupa chups cupcake tiramisu croissant. Pastry apple pie halvah cheesecake candy tiramisu cake.',
      time: '2:20 PM',
      isOnline: true,
      reactions: [
        { type: 'thumb', count: 9 },
        { type: 'heart', count: 8 },
        { type: 'smile', count: 7 },
      ],
    },
  ];

  return (
    <Card variant="outlined" sx={{ backgroundColor: '#fafafa', height: 600 }}>
      <Box sx={{ display: 'flex', height: '100%' }}>
        {/* Left Sidebar - Chat List */}
        <Box
          sx={{
            width: '25%',
            borderRight: '1px solid #e0e0e0',
            display: 'flex',
            flexDirection: 'column',
            backgroundColor: '#ffffff',
          }}
        >
          {/* Header */}
          <Box
            sx={{
              padding: 2,
              borderBottom: '1px solid #e0e0e0',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'space-between',
            }}
          >
            <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
              <Typography variant="h6" sx={{ fontWeight: 600, fontSize: '1rem' }}>
                Telegram
              </Typography>
              <ArrowDropDown />
            </Box>
            <Box sx={{ display: 'flex', gap: 0.5 }}>
              <IconButton size="small">
                <Menu fontSize="small" />
              </IconButton>
              <IconButton size="small">
                <Edit fontSize="small" />
              </IconButton>
              <IconButton size="small">
                <GridView fontSize="small" />
              </IconButton>
            </Box>
          </Box>

          {/* Chat List */}
          <Box sx={{ flex: 1, overflowY: 'auto' }}>
            {/* Pinned Section */}
            <Box>
              <Typography
                variant="caption"
                sx={{
                  padding: '8px 16px',
                  color: '#757575',
                  fontSize: '0.75rem',
                  fontWeight: 600,
                  textTransform: 'uppercase',
                }}
              >
                Pinned
              </Typography>
              <List sx={{ padding: 0 }}>
                {pinnedChats.map((chat) => (
                  <ChatListItem key={chat.id} chat={chat} />
                ))}
              </List>
            </Box>

            <Divider />

            {/* Recent Section */}
            <Box>
              <Typography
                variant="caption"
                sx={{
                  padding: '8px 16px',
                  color: '#757575',
                  fontSize: '0.75rem',
                  fontWeight: 600,
                  textTransform: 'uppercase',
                }}
              >
                Recent
              </Typography>
              <List sx={{ padding: 0 }}>
                {recentChats.map((chat) => (
                  <ChatListItem key={chat.id} chat={chat} />
                ))}
              </List>
            </Box>
          </Box>
        </Box>

        {/* Right Side - Chat Content */}
        <Box sx={{ flex: 1, display: 'flex', flexDirection: 'column', backgroundColor: '#fafafa' }}>
          {/* Chat Header */}
          <Box
            sx={{
              padding: 2,
              borderBottom: '1px solid #e0e0e0',
              backgroundColor: '#ffffff',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'space-between',
            }}
          >
            <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
              <Box
                sx={{
                  backgroundColor: '#9c27b0',
                  color: '#ffffff',
                  padding: '6px 12px',
                  borderRadius: 1,
                  display: 'flex',
                  alignItems: 'center',
                  gap: 0.5,
                }}
              >
                <Typography variant="body2" sx={{ fontWeight: 600, fontSize: '0.875rem' }}>
                  Channel Name
                </Typography>
                <GridView fontSize="small" sx={{ fontSize: '0.875rem' }} />
              </Box>
            </Box>
            <Box sx={{ display: 'flex', gap: 1 }}>
              <Button
                variant="outlined"
                size="small"
                startIcon={<VideoCall />}
                sx={{ textTransform: 'none', fontSize: '0.875rem' }}
              >
                Meet now
              </Button>
              <Button
                variant="outlined"
                size="small"
                startIcon={<Add />}
                endIcon={<ArrowDropDown />}
                sx={{ textTransform: 'none', fontSize: '0.875rem' }}
              >
                New meeting
              </Button>
            </Box>
          </Box>

          {/* Messages */}
          <Box sx={{ flex: 1, overflowY: 'auto', padding: 2 }}>
            {messages.map((msg) => (
              <ChatMessageItem key={msg.id} message={msg} />
            ))}
          </Box>

          {/* Input Area */}
          <Box
            sx={{
              padding: 2,
              borderTop: '1px solid #e0e0e0',
              backgroundColor: '#ffffff',
            }}
          >
            <TextField
              fullWidth
              placeholder="Type a message..."
              variant="outlined"
              size="small"
              InputProps={{
                endAdornment: (
                  <IconButton size="small" color="primary">
                    <SendOutlined />
                  </IconButton>
                ),
              }}
            />
          </Box>
        </Box>
      </Box>
    </Card>
  );
};

const ChatListItem: React.FC<{ chat: ChatItem }> = ({ chat }) => {
  return (
    <ListItem
      sx={{
        padding: '8px 16px',
        cursor: 'pointer',
        '&:hover': { backgroundColor: '#f5f5f5' },
      }}
    >
      <ListItemAvatar>
        <Box sx={{ position: 'relative' }}>
          <Avatar
            sx={{
              width: 40,
              height: 40,
              backgroundColor: chat.isGroup ? '#9c27b0' : '#1976d2',
              fontSize: '0.875rem',
            }}
          >
            {chat.avatar}
          </Avatar>
          {chat.isOnline && (
            <Box
              sx={{
                position: 'absolute',
                bottom: 0,
                right: 0,
                width: 12,
                height: 12,
                borderRadius: '50%',
                backgroundColor: '#4caf50',
                border: '2px solid #ffffff',
              }}
            />
          )}
        </Box>
      </ListItemAvatar>
      <ListItemText
        primary={
          <Typography variant="body2" sx={{ fontWeight: 500, fontSize: '0.875rem' }}>
            {chat.name}
          </Typography>
        }
        secondary={
          <Typography
            variant="caption"
            sx={{
              fontSize: '0.75rem',
              color: '#757575',
              overflow: 'hidden',
              textOverflow: 'ellipsis',
              whiteSpace: 'nowrap',
            }}
          >
            {chat.lastMessage}
          </Typography>
        }
      />
      <Typography variant="caption" sx={{ fontSize: '0.75rem', color: '#757575', marginLeft: 1 }}>
        {chat.time}
      </Typography>
    </ListItem>
  );
};

const ChatMessageItem: React.FC<{ message: ChatMessage }> = ({ message }) => {
  return (
    <Box sx={{ display: 'flex', gap: 1, marginBottom: 2 }}>
      <Box sx={{ position: 'relative' }}>
        <Avatar
          sx={{
            width: 36,
            height: 36,
            backgroundColor: '#1976d2',
            fontSize: '0.75rem',
          }}
        >
          {message.avatar}
        </Avatar>
        {message.isOnline && (
          <Box
            sx={{
              position: 'absolute',
              bottom: 0,
              right: 0,
              width: 10,
              height: 10,
              borderRadius: '50%',
              backgroundColor: '#4caf50',
              border: '2px solid #ffffff',
            }}
          />
        )}
      </Box>
      <Box sx={{ flex: 1 }}>
        <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, marginBottom: 0.5 }}>
          <Typography variant="body2" sx={{ fontWeight: 600, fontSize: '0.875rem' }}>
            {message.sender}
          </Typography>
          <Typography variant="caption" sx={{ fontSize: '0.75rem', color: '#757575' }}>
            {message.time}
          </Typography>
        </Box>
        {message.attachment ? (
          <Paper
            sx={{
              padding: 1.5,
              backgroundColor: '#f5f5f5',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'space-between',
              marginBottom: 1,
            }}
          >
            <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
              <Typography variant="body2" sx={{ fontSize: '0.875rem' }}>
                {message.message}
              </Typography>
            </Box>
            <IconButton size="small">
              <MoreVert fontSize="small" />
            </IconButton>
          </Paper>
        ) : (
          <Paper
            sx={{
              padding: 1.5,
              backgroundColor: '#ffffff',
              borderRadius: 2,
              marginBottom: message.reactions ? 1 : 0,
            }}
          >
            <Typography variant="body2" sx={{ fontSize: '0.875rem', color: '#424242' }}>
              {message.message}
            </Typography>
          </Paper>
        )}
        {message.reactions && (
          <Box sx={{ display: 'flex', gap: 1, marginTop: 0.5 }}>
            {message.reactions.map((reaction, index) => (
              <Box
                key={index}
                sx={{
                  display: 'flex',
                  alignItems: 'center',
                  gap: 0.5,
                  padding: '2px 8px',
                  backgroundColor: '#f5f5f5',
                  borderRadius: 1,
                  fontSize: '0.75rem',
                }}
              >
                {reaction.type === 'thumb' && <ThumbUp sx={{ fontSize: '0.875rem' }} />}
                {reaction.type === 'heart' && <Favorite sx={{ fontSize: '0.875rem', color: '#f44336' }} />}
                {reaction.type === 'smile' && <SentimentSatisfied sx={{ fontSize: '0.875rem' }} />}
                <Typography variant="caption" sx={{ fontSize: '0.75rem' }}>
                  {reaction.count}
                </Typography>
              </Box>
            ))}
          </Box>
        )}
      </Box>
    </Box>
  );
};

export default RessaDWM;

