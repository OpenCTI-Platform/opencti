import { createLogger, defineConfig, transformWithEsbuild } from 'vite';
import react from '@vitejs/plugin-react';
import * as path from 'node:path';
import relay from 'vite-plugin-relay';
import { viteStaticCopy } from 'vite-plugin-static-copy'

// to avoid multiple reload when discovering new dependencies after a going on a lazy (not precedently) loaded route we pre optmize these dependencies
const depsToOptimize = [
  "@mui/icons-material",
  "@mui/material/Menu",
  "@mui/material/Divider",
  "@mui/material/MenuItem",
  "@mui/material/Tooltip",
  "@mui/material/Snackbar",
  "@mui/material/AlertTitle",
  "@mui/material/Dialog",
  "@mui/material/DialogActions",
  "@mui/material/DialogContent",
  "@mui/material/DialogTitle",
  "@mui/material/DialogContentText",
  "@mui/material/MenuList",
  "@mui/material/ListItemIcon",
  "@mui/material/ListItemText",
  "@mui/material/Drawer",
  "@mui/styles/withStyles",
  "@mui/material/TextField",
  "@mui/material/InputAdornment",
  "uuid",
  "@mui/material/FormControl",
  "@mui/material/InputLabel",
  "@mui/material/ListSubheader",
  "@mui/material/Select",
  "@mui/material/Slide",
  "react-mde",
  "@mui/material/FormHelperText",
  "@mui/icons-material/SentimentVeryDissatisfied",
  "@mui/icons-material/SentimentDissatisfied",
  "@mui/icons-material/SentimentSatisfied",
  "@mui/icons-material/SentimentSatisfiedAltOutlined",
  "@mui/icons-material/SentimentVerySatisfied",
  "@mui/material/Rating",
  "@mui/material/Fab",
  "js-base64",
  "remark-parse",
  "remark-flexible-markers",
  "remark-gfm",
  "@mui/material/Autocomplete",
  "three-spritetext",
  "@mui/material/Avatar",
  "@mui/material/FormGroup",
  "@mui/material/FormControlLabel",
  "react-color",
  "@mui/material/Popover",
  "@mui/material/List",
  "@mui/material/ListItem",
  "@mui/material/ListItemSecondaryAction",
  "@mui/material/Badge",
  "@mui/material/Chip",
  "@mui/material/Grid",
  "@mui/material/Accordion",
  "@mui/material/AccordionDetails",
  "@mui/material/AccordionSummary",
  "@mui/styles/withTheme",
  'use-analytics',
  'analytics',
  '@analytics/google-analytics',
  '@mui/material/AppBar',
  '@mui/material/Toolbar',
  '@mui/material/IconButton',
  "@mui/material/Card",
  "@mui/material/CardContent",
  "@mui/material/colors",
  "react-leaflet",
  "leaflet",
  "react-apexcharts",
  "react-grid-layout",
  "@mui/icons-material/MoreVert",
  "@mui/material/CardActionArea",
  "@mui/material/CardHeader",
  "js-file-download",
  "@mui/material/ToggleButtonGroup",
  "@mui/material/ToggleButton",
  "@mui/x-date-pickers/DatePicker",
  "@mui/lab/Timeline",
  "@mui/lab/TimelineItem",
  "@mui/lab/TimelineSeparator",
  "@mui/lab/TimelineConnector",
  "@mui/lab/TimelineContent",
  "@mui/lab/TimelineOppositeContent",
  "@mui/lab/TimelineDot",
  "@mui/material/Stepper",
  "@mui/material/Step",
  "@mui/material/StepButton",
  "@mui/material/StepLabel",
  "@mui/material/Switch",
  "@mui/material/SpeedDial",
  "@mui/material/SpeedDialAction",
  "react-csv",
  "html-to-image",
  "pdfmake",
  "@mui/material/Skeleton",
  "react-virtualized",
  "@mui/material/Tabs",
  "@mui/material/Tab",
  "@mui/x-date-pickers/DateTimePicker",
  "formik-mui-lab",
  "@ckeditor/ckeditor5-react",
  "@mui/material/Slider",
  "convert",
  "react-syntax-highlighter",
  "react-syntax-highlighter/dist/esm/styles/prism",
  "axios",
  "html-to-pdfmake",
  "react-pdf",
  "@mui/material/Radio",
  "@mui/material/Table",
  "@mui/material/TableHead",
  "@mui/material/TableBody",
  "@mui/material/TableCell",
  "@mui/material/TableContainer",
  "@mui/material/TableRow",
  "react-force-graph-2d",
  "react-force-graph-3d",
  "react-rectangle-selection",
  "@mui/material/SpeedDialIcon",
  "react-timeline-range-slider",
  "recharts",
  "@mui/material/Collapse",
  "@mui/x-date-pickers/TimePicker",
  "react-material-ui-carousel",
  "@mui/material/LinearProgress",
  "@rjsf/mui",
  "@mui/icons-material/LocalPoliceOutlined",
  "@rjsf/utils",
  "@mui/material/ListItemAvatar",
  "@mui/lab/Alert",
  "reactflow",
  "@mui/icons-material/ExpandMore",
  "@mui/icons-material/TableView",
  "@mui/icons-material/ArrowForwardIosSharp",
  "d3-hierarchy",
  "d3-timer",
  "@mui/icons-material/Share",
  "@mui/icons-material/ContentCopy",
  "@mui/icons-material/Delete",
  "@mui/lab/LoadingButton",
  "@mui/material/Breadcrumbs",
  "classnames",
  "react-draggable",
  "react-beautiful-dnd"
]

const logger = createLogger()
const loggerError = logger.error

logger.error = (msg, options) => {
  // Ignore jsx syntax error as it taken into account in a custom plugin
  if (msg.includes('The JSX syntax extension is not currently enabled')) return
  loggerError(msg, options)
}

const basePath = "";

const backProxy = (ws = false) => ({
  target: process.env.BACK_END_URL ?? 'http://localhost:4000',
  changeOrigin: true,
  ws,
})

// https://vitejs.dev/config/
export default defineConfig({
  build: {
    target: ['chrome58'],
  },

  resolve: {
    alias: {
      '@components': path.resolve(__dirname, './src/private/components'),
      'src': path.resolve(__dirname, './src'),
    },
    extensions: ['.tsx', '.jsx', '.ts', '.js', '.json'],
  },

  optimizeDeps: {
    include: [
      ...depsToOptimize,
      'ckeditor5-custom-build/build/ckeditor',
    ],
  },

  customLogger: logger,

  plugins: [
    viteStaticCopy({
      targets: [
        {
          src: 'src/static/ext/*',
          dest: 'static/ext'
        }
      ]
    }),
    {
      name: 'html-transform',
      enforce: "pre",
      apply: 'serve',
      transformIndexHtml(html) {
        return html.replace(/%BASE_PATH%/g, basePath)
          .replace(/%APP_TITLE%/g, "OpenCTI Dev")
          .replace(/%APP_DESCRIPTION%/g, "OpenCTI Development platform")
          .replace(/%APP_FAVICON%/g, `${basePath}/static/ext/favicon.png`)
          .replace(/%APP_MANIFEST%/g, `${basePath}/static/ext/manifest.json`)
      }
    },
    {
      name: 'treat-js-files-as-jsx',
      async transform(code, id) {
        if (!id.match(/src\/.*\.js$/)) return null;
        // Use the exposed transform from vite, instead of directly
        // transforming with esbuild
        return transformWithEsbuild(code, id, {
          loader: 'tsx',
          jsx: 'automatic',
        });
      },
    },
    react(),
    relay
  ],

  server: {
    port: 3000,
    proxy: {
      '/logout': backProxy(),
      '/stream': backProxy(),
      '/storage': backProxy(),
      '/taxii2': backProxy(),
      '/feeds': backProxy(),
      '/graphql': backProxy(true),
      '/auth': backProxy(),
      '/static/flags': backProxy(),
    },
  },
});
