import { createLogger, defineConfig, transformWithEsbuild } from 'vite';
import react from '@vitejs/plugin-react';
import * as path from 'node:path';
import relay from 'vite-plugin-relay';
import { viteStaticCopy } from 'vite-plugin-static-copy';

// to avoid multiple reload when discovering new dependencies after a going on a lazy (not precedently) loaded route we pre optmize these dependencies
const depsToOptimize = [
  "@analytics/google-analytics",
  "@ckeditor/ckeditor5-react",
  "@hello-pangea/dnd",
  "@mui/icons-material",
  "@mui/icons-material/ArrowForwardIosSharp",
  "@mui/icons-material/ChevronRight",
  "@mui/icons-material/ContentCopy",
  "@mui/icons-material/Delete",
  "@mui/icons-material/ExpandMore",
  "@mui/icons-material/HistoryEdu",
  "@mui/icons-material/LocalPoliceOutlined",
  "@mui/icons-material/MoreVert",
  "@mui/icons-material/SentimentDissatisfied",
  "@mui/icons-material/SentimentSatisfied",
  "@mui/icons-material/SentimentSatisfiedAltOutlined",
  "@mui/icons-material/SentimentVeryDissatisfied",
  "@mui/icons-material/SentimentVerySatisfied",
  "@mui/icons-material/Share",
  "@mui/icons-material/TableView",
  "@mui/lab/Alert",
  "@mui/lab/LoadingButton",
  "@mui/lab/Timeline",
  "@mui/lab/TimelineConnector",
  "@mui/lab/TimelineContent",
  "@mui/lab/TimelineDot",
  "@mui/lab/TimelineItem",
  "@mui/lab/TimelineOppositeContent",
  "@mui/lab/TimelineSeparator",
  "@mui/material/Accordion",
  "@mui/material/AccordionDetails",
  "@mui/material/AccordionSummary",
  "@mui/material/AlertTitle",
  "@mui/material/AppBar",
  "@mui/material/Autocomplete",
  "@mui/material/Avatar",
  "@mui/material/Badge",
  "@mui/material/Breadcrumbs",
  "@mui/material/Card",
  "@mui/material/CardActionArea",
  "@mui/material/CardContent",
  "@mui/material/CardHeader",
  "@mui/material/Chip",
  "@mui/material/Collapse",
  "@mui/material/Dialog",
  "@mui/material/DialogActions",
  "@mui/material/DialogContent",
  "@mui/material/DialogContentText",
  "@mui/material/DialogTitle",
  "@mui/material/Divider",
  "@mui/material/Drawer",
  "@mui/material/Fab",
  "@mui/material/FormControl",
  "@mui/material/FormControlLabel",
  "@mui/material/FormGroup",
  "@mui/material/FormHelperText",
  "@mui/material/Grid",
  "@mui/material/IconButton",
  "@mui/material/InputAdornment",
  "@mui/material/InputLabel",
  "@mui/material/LinearProgress",
  "@mui/material/List",
  "@mui/material/ListItem",
  "@mui/material/ListItemAvatar",
  "@mui/material/ListItemButton",
  "@mui/material/ListItemIcon",
  "@mui/material/ListItemSecondaryAction",
  "@mui/material/ListItemText",
  "@mui/material/ListSubheader",
  "@mui/material/Menu",
  "@mui/material/MenuItem",
  "@mui/material/MenuList",
  "@mui/material/Popover",
  "@mui/material/Radio",
  "@mui/material/Rating",
  "@mui/material/Select",
  "@mui/material/Skeleton",
  "@mui/material/Slide",
  "@mui/material/Slider",
  "@mui/material/Snackbar",
  "@mui/material/SpeedDial",
  "@mui/material/SpeedDialAction",
  "@mui/material/SpeedDialIcon",
  "@mui/material/Step",
  "@mui/material/StepButton",
  "@mui/material/StepLabel",
  "@mui/material/Stepper",
  "@mui/material/Switch",
  "@mui/material/Tab",
  "@mui/material/Table",
  "@mui/material/TableBody",
  "@mui/material/TableCell",
  "@mui/material/TableContainer",
  "@mui/material/TableHead",
  "@mui/material/TableRow",
  "@mui/material/Tabs",
  "@mui/material/TextField",
  "@mui/material/ToggleButton",
  "@mui/material/ToggleButtonGroup",
  "@mui/material/Toolbar",
  "@mui/material/Tooltip",
  "@mui/material/colors",
  "@mui/styles/withStyles",
  "@mui/styles/withTheme",
  "@mui/x-date-pickers/DatePicker",
  "@mui/x-date-pickers/DateTimePicker",
  "@mui/x-date-pickers/TimePicker",
  "@rjsf/mui",
  "@rjsf/utils",
  "analytics",
  "axios",
  "buffer",
  "ckeditor5",
  "ckeditor5/translations/de.js",
  "ckeditor5/translations/en.js",
  "ckeditor5/translations/es.js",
  "ckeditor5/translations/fr.js",
  "ckeditor5/translations/ja.js",
  "ckeditor5/translations/ko.js",
  "ckeditor5/translations/zh.js",
  "classnames",
  "convert",
  "date-fns",
  "d3-hierarchy",
  "d3-timer",
  "dompurify",
  "formik-mui-lab",
  "html-to-image",
  "html-to-pdfmake",
  "js-base64",
  "js-file-download",
  "leaflet",
  "markdown-to-jsx",
  "marked",
  "moment/moment",
  "pdfmake",
  "pdfmake/build/pdfmake",
  "react-apexcharts",
  "react-color",
  "react-csv",
  "react-dom/server",
  "react-draggable",
  "react-force-graph-2d",
  "react-force-graph-3d",
  "react-grid-layout",
  "react-leaflet",
  "react-material-ui-carousel",
  "react-mde",
  "react-pdf",
  "react-rectangle-selection",
  "react-syntax-highlighter",
  "react-syntax-highlighter/dist/esm/styles/prism",
  "react-virtualized",
  "react-wordcloud",
  "reactflow",
  "recharts",
  "remark-flexible-markers",
  "remark-gfm",
  "remark-parse",
  "three-spritetext",
  "use-analytics",
  "uuid",
  "d3-scale",
  "react-compound-slider"
 ];

const logger = createLogger();
const loggerError = logger.error;

logger.error = (msg, options) => {
  // Ignore jsx syntax error as it taken into account in a custom plugin
  if (msg.includes('The JSX syntax extension is not currently enabled')) return
  loggerError(msg, options)
};

const basePath = "";

const backProxy = (ws = false) => ({
  target: process.env.BACK_END_URL ?? 'http://localhost:4000',
  changeOrigin: true,
  ws,
});

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
    include: depsToOptimize,
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
