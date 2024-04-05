// vite.config.mts
import { createLogger, defineConfig, transformWithEsbuild } from "file:///C:/Users/FrancoisGrunert/IdeaProjects/opencti/opencti-platform/opencti-front/node_modules/vite/dist/node/index.js";
import react from "file:///C:/Users/FrancoisGrunert/IdeaProjects/opencti/opencti-platform/opencti-front/node_modules/@vitejs/plugin-react/dist/index.mjs";
import * as path from "node:path";
import relay from "file:///C:/Users/FrancoisGrunert/IdeaProjects/opencti/opencti-platform/opencti-front/node_modules/vite-plugin-relay/dist/plugin.js";
import { viteStaticCopy } from "file:///C:/Users/FrancoisGrunert/IdeaProjects/opencti/opencti-platform/opencti-front/node_modules/vite-plugin-static-copy/dist/index.js";
var __vite_injected_original_dirname = "C:\\Users\\FrancoisGrunert\\IdeaProjects\\opencti\\opencti-platform\\opencti-front";
var depsToOptimize = [
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
  "use-analytics",
  "analytics",
  "@analytics/google-analytics",
  "@mui/material/AppBar",
  "@mui/material/Toolbar",
  "@mui/material/IconButton",
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
  "@mui/material/Breadcrumbs"
];
var logger = createLogger();
var loggerError = logger.error;
logger.error = (msg, options) => {
  if (msg.includes("The JSX syntax extension is not currently enabled"))
    return;
  loggerError(msg, options);
};
var basePath = "";
var backProxy = (ws = false) => ({
  target: process.env.BACK_END_URL ?? "http://localhost:4000",
  changeOrigin: true,
  ws
});
var vite_config_default = defineConfig({
  build: {
    target: ["chrome58"]
  },
  resolve: {
    alias: {
      "@components": path.resolve(__vite_injected_original_dirname, "./src/private/components")
    },
    extensions: [".tsx", ".jsx", ".ts", ".js", ".json"]
  },
  optimizeDeps: {
    include: [
      ...depsToOptimize,
      "ckeditor5-custom-build/build/ckeditor"
    ]
  },
  customLogger: logger,
  plugins: [
    viteStaticCopy({
      targets: [
        {
          src: "src/static/ext/*",
          dest: "static/ext"
        }
      ]
    }),
    {
      name: "html-transform",
      enforce: "pre",
      apply: "serve",
      transformIndexHtml(html) {
        return html.replace(/%BASE_PATH%/g, basePath).replace(/%APP_TITLE%/g, "OpenCTI Dev").replace(/%APP_DESCRIPTION%/g, "OpenCTI Development platform").replace(/%APP_FAVICON%/g, `${basePath}/static/ext/favicon.png`).replace(/%APP_MANIFEST%/g, `${basePath}/static/ext/manifest.json`);
      }
    },
    {
      name: "treat-js-files-as-jsx",
      async transform(code, id) {
        if (!id.match(/src\/.*\.js$/))
          return null;
        return transformWithEsbuild(code, id, {
          loader: "tsx",
          jsx: "automatic"
        });
      }
    },
    react(),
    relay
  ],
  server: {
    port: 3e3,
    proxy: {
      "/logout": backProxy(),
      "/stream": backProxy(),
      "/storage": backProxy(),
      "/taxii2": backProxy(),
      "/feeds": backProxy(),
      "/graphql": backProxy(true),
      "/auth": backProxy(),
      "/static/flags": backProxy()
    }
  }
});
export {
  vite_config_default as default
};
//# sourceMappingURL=data:application/json;base64,ewogICJ2ZXJzaW9uIjogMywKICAic291cmNlcyI6IFsidml0ZS5jb25maWcubXRzIl0sCiAgInNvdXJjZXNDb250ZW50IjogWyJjb25zdCBfX3ZpdGVfaW5qZWN0ZWRfb3JpZ2luYWxfZGlybmFtZSA9IFwiQzpcXFxcVXNlcnNcXFxcRnJhbmNvaXNHcnVuZXJ0XFxcXElkZWFQcm9qZWN0c1xcXFxvcGVuY3RpXFxcXG9wZW5jdGktcGxhdGZvcm1cXFxcb3BlbmN0aS1mcm9udFwiO2NvbnN0IF9fdml0ZV9pbmplY3RlZF9vcmlnaW5hbF9maWxlbmFtZSA9IFwiQzpcXFxcVXNlcnNcXFxcRnJhbmNvaXNHcnVuZXJ0XFxcXElkZWFQcm9qZWN0c1xcXFxvcGVuY3RpXFxcXG9wZW5jdGktcGxhdGZvcm1cXFxcb3BlbmN0aS1mcm9udFxcXFx2aXRlLmNvbmZpZy5tdHNcIjtjb25zdCBfX3ZpdGVfaW5qZWN0ZWRfb3JpZ2luYWxfaW1wb3J0X21ldGFfdXJsID0gXCJmaWxlOi8vL0M6L1VzZXJzL0ZyYW5jb2lzR3J1bmVydC9JZGVhUHJvamVjdHMvb3BlbmN0aS9vcGVuY3RpLXBsYXRmb3JtL29wZW5jdGktZnJvbnQvdml0ZS5jb25maWcubXRzXCI7aW1wb3J0IHsgY3JlYXRlTG9nZ2VyLCBkZWZpbmVDb25maWcsIHRyYW5zZm9ybVdpdGhFc2J1aWxkIH0gZnJvbSAndml0ZSc7XG5pbXBvcnQgcmVhY3QgZnJvbSAnQHZpdGVqcy9wbHVnaW4tcmVhY3QnO1xuaW1wb3J0ICogYXMgcGF0aCBmcm9tICdub2RlOnBhdGgnO1xuaW1wb3J0IHJlbGF5IGZyb20gJ3ZpdGUtcGx1Z2luLXJlbGF5JztcbmltcG9ydCB7IHZpdGVTdGF0aWNDb3B5IH0gZnJvbSAndml0ZS1wbHVnaW4tc3RhdGljLWNvcHknXG5cbi8vIHRvIGF2b2lkIG11bHRpcGxlIHJlbG9hZCB3aGVuIGRpc2NvdmVyaW5nIG5ldyBkZXBlbmRlbmNpZXMgYWZ0ZXIgYSBnb2luZyBvbiBhIGxhenkgKG5vdCBwcmVjZWRlbnRseSkgbG9hZGVkIHJvdXRlIHdlIHByZSBvcHRtaXplIHRoZXNlIGRlcGVuZGVuY2llc1xuY29uc3QgZGVwc1RvT3B0aW1pemUgPSBbXG4gIFwiQG11aS9pY29ucy1tYXRlcmlhbFwiLFxuICBcIkBtdWkvbWF0ZXJpYWwvTWVudVwiLFxuICBcIkBtdWkvbWF0ZXJpYWwvRGl2aWRlclwiLFxuICBcIkBtdWkvbWF0ZXJpYWwvTWVudUl0ZW1cIixcbiAgXCJAbXVpL21hdGVyaWFsL1Rvb2x0aXBcIixcbiAgXCJAbXVpL21hdGVyaWFsL1NuYWNrYmFyXCIsXG4gIFwiQG11aS9tYXRlcmlhbC9BbGVydFRpdGxlXCIsXG4gIFwiQG11aS9tYXRlcmlhbC9EaWFsb2dcIixcbiAgXCJAbXVpL21hdGVyaWFsL0RpYWxvZ0FjdGlvbnNcIixcbiAgXCJAbXVpL21hdGVyaWFsL0RpYWxvZ0NvbnRlbnRcIixcbiAgXCJAbXVpL21hdGVyaWFsL0RpYWxvZ1RpdGxlXCIsXG4gIFwiQG11aS9tYXRlcmlhbC9EaWFsb2dDb250ZW50VGV4dFwiLFxuICBcIkBtdWkvbWF0ZXJpYWwvTWVudUxpc3RcIixcbiAgXCJAbXVpL21hdGVyaWFsL0xpc3RJdGVtSWNvblwiLFxuICBcIkBtdWkvbWF0ZXJpYWwvTGlzdEl0ZW1UZXh0XCIsXG4gIFwiQG11aS9tYXRlcmlhbC9EcmF3ZXJcIixcbiAgXCJAbXVpL3N0eWxlcy93aXRoU3R5bGVzXCIsXG4gIFwiQG11aS9tYXRlcmlhbC9UZXh0RmllbGRcIixcbiAgXCJAbXVpL21hdGVyaWFsL0lucHV0QWRvcm5tZW50XCIsXG4gIFwidXVpZFwiLFxuICBcIkBtdWkvbWF0ZXJpYWwvRm9ybUNvbnRyb2xcIixcbiAgXCJAbXVpL21hdGVyaWFsL0lucHV0TGFiZWxcIixcbiAgXCJAbXVpL21hdGVyaWFsL0xpc3RTdWJoZWFkZXJcIixcbiAgXCJAbXVpL21hdGVyaWFsL1NlbGVjdFwiLFxuICBcIkBtdWkvbWF0ZXJpYWwvU2xpZGVcIixcbiAgXCJyZWFjdC1tZGVcIixcbiAgXCJAbXVpL21hdGVyaWFsL0Zvcm1IZWxwZXJUZXh0XCIsXG4gIFwiQG11aS9pY29ucy1tYXRlcmlhbC9TZW50aW1lbnRWZXJ5RGlzc2F0aXNmaWVkXCIsXG4gIFwiQG11aS9pY29ucy1tYXRlcmlhbC9TZW50aW1lbnREaXNzYXRpc2ZpZWRcIixcbiAgXCJAbXVpL2ljb25zLW1hdGVyaWFsL1NlbnRpbWVudFNhdGlzZmllZFwiLFxuICBcIkBtdWkvaWNvbnMtbWF0ZXJpYWwvU2VudGltZW50U2F0aXNmaWVkQWx0T3V0bGluZWRcIixcbiAgXCJAbXVpL2ljb25zLW1hdGVyaWFsL1NlbnRpbWVudFZlcnlTYXRpc2ZpZWRcIixcbiAgXCJAbXVpL21hdGVyaWFsL1JhdGluZ1wiLFxuICBcIkBtdWkvbWF0ZXJpYWwvRmFiXCIsXG4gIFwianMtYmFzZTY0XCIsXG4gIFwicmVtYXJrLXBhcnNlXCIsXG4gIFwicmVtYXJrLWZsZXhpYmxlLW1hcmtlcnNcIixcbiAgXCJyZW1hcmstZ2ZtXCIsXG4gIFwiQG11aS9tYXRlcmlhbC9BdXRvY29tcGxldGVcIixcbiAgXCJ0aHJlZS1zcHJpdGV0ZXh0XCIsXG4gIFwiQG11aS9tYXRlcmlhbC9BdmF0YXJcIixcbiAgXCJAbXVpL21hdGVyaWFsL0Zvcm1Hcm91cFwiLFxuICBcIkBtdWkvbWF0ZXJpYWwvRm9ybUNvbnRyb2xMYWJlbFwiLFxuICBcInJlYWN0LWNvbG9yXCIsXG4gIFwiQG11aS9tYXRlcmlhbC9Qb3BvdmVyXCIsXG4gIFwiQG11aS9tYXRlcmlhbC9MaXN0XCIsXG4gIFwiQG11aS9tYXRlcmlhbC9MaXN0SXRlbVwiLFxuICBcIkBtdWkvbWF0ZXJpYWwvTGlzdEl0ZW1TZWNvbmRhcnlBY3Rpb25cIixcbiAgXCJAbXVpL21hdGVyaWFsL0JhZGdlXCIsXG4gIFwiQG11aS9tYXRlcmlhbC9DaGlwXCIsXG4gIFwiQG11aS9tYXRlcmlhbC9HcmlkXCIsXG4gIFwiQG11aS9tYXRlcmlhbC9BY2NvcmRpb25cIixcbiAgXCJAbXVpL21hdGVyaWFsL0FjY29yZGlvbkRldGFpbHNcIixcbiAgXCJAbXVpL21hdGVyaWFsL0FjY29yZGlvblN1bW1hcnlcIixcbiAgXCJAbXVpL3N0eWxlcy93aXRoVGhlbWVcIixcbiAgJ3VzZS1hbmFseXRpY3MnLFxuICAnYW5hbHl0aWNzJyxcbiAgJ0BhbmFseXRpY3MvZ29vZ2xlLWFuYWx5dGljcycsXG4gICdAbXVpL21hdGVyaWFsL0FwcEJhcicsXG4gICdAbXVpL21hdGVyaWFsL1Rvb2xiYXInLFxuICAnQG11aS9tYXRlcmlhbC9JY29uQnV0dG9uJyxcbiAgXCJAbXVpL21hdGVyaWFsL0NhcmRcIixcbiAgXCJAbXVpL21hdGVyaWFsL0NhcmRDb250ZW50XCIsXG4gIFwiQG11aS9tYXRlcmlhbC9jb2xvcnNcIixcbiAgXCJyZWFjdC1sZWFmbGV0XCIsXG4gIFwibGVhZmxldFwiLFxuICBcInJlYWN0LWFwZXhjaGFydHNcIixcbiAgXCJyZWFjdC1ncmlkLWxheW91dFwiLFxuICBcIkBtdWkvaWNvbnMtbWF0ZXJpYWwvTW9yZVZlcnRcIixcbiAgXCJAbXVpL21hdGVyaWFsL0NhcmRBY3Rpb25BcmVhXCIsXG4gIFwiQG11aS9tYXRlcmlhbC9DYXJkSGVhZGVyXCIsXG4gIFwianMtZmlsZS1kb3dubG9hZFwiLFxuICBcIkBtdWkvbWF0ZXJpYWwvVG9nZ2xlQnV0dG9uR3JvdXBcIixcbiAgXCJAbXVpL21hdGVyaWFsL1RvZ2dsZUJ1dHRvblwiLFxuICBcIkBtdWkveC1kYXRlLXBpY2tlcnMvRGF0ZVBpY2tlclwiLFxuICBcIkBtdWkvbGFiL1RpbWVsaW5lXCIsXG4gIFwiQG11aS9sYWIvVGltZWxpbmVJdGVtXCIsXG4gIFwiQG11aS9sYWIvVGltZWxpbmVTZXBhcmF0b3JcIixcbiAgXCJAbXVpL2xhYi9UaW1lbGluZUNvbm5lY3RvclwiLFxuICBcIkBtdWkvbGFiL1RpbWVsaW5lQ29udGVudFwiLFxuICBcIkBtdWkvbGFiL1RpbWVsaW5lT3Bwb3NpdGVDb250ZW50XCIsXG4gIFwiQG11aS9sYWIvVGltZWxpbmVEb3RcIixcbiAgXCJAbXVpL21hdGVyaWFsL1N0ZXBwZXJcIixcbiAgXCJAbXVpL21hdGVyaWFsL1N0ZXBcIixcbiAgXCJAbXVpL21hdGVyaWFsL1N0ZXBCdXR0b25cIixcbiAgXCJAbXVpL21hdGVyaWFsL1N0ZXBMYWJlbFwiLFxuICBcIkBtdWkvbWF0ZXJpYWwvU3dpdGNoXCIsXG4gIFwiQG11aS9tYXRlcmlhbC9TcGVlZERpYWxcIixcbiAgXCJAbXVpL21hdGVyaWFsL1NwZWVkRGlhbEFjdGlvblwiLFxuICBcInJlYWN0LWNzdlwiLFxuICBcImh0bWwtdG8taW1hZ2VcIixcbiAgXCJwZGZtYWtlXCIsXG4gIFwiQG11aS9tYXRlcmlhbC9Ta2VsZXRvblwiLFxuICBcInJlYWN0LXZpcnR1YWxpemVkXCIsXG4gIFwiQG11aS9tYXRlcmlhbC9UYWJzXCIsXG4gIFwiQG11aS9tYXRlcmlhbC9UYWJcIixcbiAgXCJAbXVpL3gtZGF0ZS1waWNrZXJzL0RhdGVUaW1lUGlja2VyXCIsXG4gIFwiZm9ybWlrLW11aS1sYWJcIixcbiAgXCJAY2tlZGl0b3IvY2tlZGl0b3I1LXJlYWN0XCIsXG4gIFwiQG11aS9tYXRlcmlhbC9TbGlkZXJcIixcbiAgXCJjb252ZXJ0XCIsXG4gIFwicmVhY3Qtc3ludGF4LWhpZ2hsaWdodGVyXCIsXG4gIFwicmVhY3Qtc3ludGF4LWhpZ2hsaWdodGVyL2Rpc3QvZXNtL3N0eWxlcy9wcmlzbVwiLFxuICBcImF4aW9zXCIsXG4gIFwiaHRtbC10by1wZGZtYWtlXCIsXG4gIFwicmVhY3QtcGRmXCIsXG4gIFwiQG11aS9tYXRlcmlhbC9SYWRpb1wiLFxuICBcIkBtdWkvbWF0ZXJpYWwvVGFibGVcIixcbiAgXCJAbXVpL21hdGVyaWFsL1RhYmxlSGVhZFwiLFxuICBcIkBtdWkvbWF0ZXJpYWwvVGFibGVCb2R5XCIsXG4gIFwiQG11aS9tYXRlcmlhbC9UYWJsZUNlbGxcIixcbiAgXCJAbXVpL21hdGVyaWFsL1RhYmxlQ29udGFpbmVyXCIsXG4gIFwiQG11aS9tYXRlcmlhbC9UYWJsZVJvd1wiLFxuICBcInJlYWN0LWZvcmNlLWdyYXBoLTJkXCIsXG4gIFwicmVhY3QtZm9yY2UtZ3JhcGgtM2RcIixcbiAgXCJyZWFjdC1yZWN0YW5nbGUtc2VsZWN0aW9uXCIsXG4gIFwiQG11aS9tYXRlcmlhbC9TcGVlZERpYWxJY29uXCIsXG4gIFwicmVhY3QtdGltZWxpbmUtcmFuZ2Utc2xpZGVyXCIsXG4gIFwicmVjaGFydHNcIixcbiAgXCJAbXVpL21hdGVyaWFsL0NvbGxhcHNlXCIsXG4gIFwiQG11aS94LWRhdGUtcGlja2Vycy9UaW1lUGlja2VyXCIsXG4gIFwicmVhY3QtbWF0ZXJpYWwtdWktY2Fyb3VzZWxcIixcbiAgXCJAbXVpL21hdGVyaWFsL0xpbmVhclByb2dyZXNzXCIsXG4gIFwiQHJqc2YvbXVpXCIsXG4gIFwiQG11aS9pY29ucy1tYXRlcmlhbC9Mb2NhbFBvbGljZU91dGxpbmVkXCIsXG4gIFwiQHJqc2YvdXRpbHNcIixcbiAgXCJAbXVpL21hdGVyaWFsL0xpc3RJdGVtQXZhdGFyXCIsXG4gIFwiQG11aS9sYWIvQWxlcnRcIixcbiAgXCJyZWFjdGZsb3dcIixcbiAgXCJAbXVpL2ljb25zLW1hdGVyaWFsL0V4cGFuZE1vcmVcIixcbiAgXCJAbXVpL2ljb25zLW1hdGVyaWFsL1RhYmxlVmlld1wiLFxuICBcIkBtdWkvaWNvbnMtbWF0ZXJpYWwvQXJyb3dGb3J3YXJkSW9zU2hhcnBcIixcbiAgXCJkMy1oaWVyYXJjaHlcIixcbiAgXCJkMy10aW1lclwiLFxuICBcIkBtdWkvaWNvbnMtbWF0ZXJpYWwvU2hhcmVcIixcbiAgXCJAbXVpL2ljb25zLW1hdGVyaWFsL0NvbnRlbnRDb3B5XCIsXG4gIFwiQG11aS9pY29ucy1tYXRlcmlhbC9EZWxldGVcIixcbiAgXCJAbXVpL2xhYi9Mb2FkaW5nQnV0dG9uXCIsXG4gIFwiQG11aS9tYXRlcmlhbC9CcmVhZGNydW1ic1wiLFxuXVxuXG5jb25zdCBsb2dnZXIgPSBjcmVhdGVMb2dnZXIoKVxuY29uc3QgbG9nZ2VyRXJyb3IgPSBsb2dnZXIuZXJyb3JcblxubG9nZ2VyLmVycm9yID0gKG1zZywgb3B0aW9ucykgPT4ge1xuICAvLyBJZ25vcmUganN4IHN5bnRheCBlcnJvciBhcyBpdCB0YWtlbiBpbnRvIGFjY291bnQgaW4gYSBjdXN0b20gcGx1Z2luXG4gIGlmIChtc2cuaW5jbHVkZXMoJ1RoZSBKU1ggc3ludGF4IGV4dGVuc2lvbiBpcyBub3QgY3VycmVudGx5IGVuYWJsZWQnKSkgcmV0dXJuXG4gIGxvZ2dlckVycm9yKG1zZywgb3B0aW9ucylcbn1cblxuY29uc3QgYmFzZVBhdGggPSBcIlwiO1xuXG5jb25zdCBiYWNrUHJveHkgPSAod3MgPSBmYWxzZSkgPT4gKHtcbiAgdGFyZ2V0OiBwcm9jZXNzLmVudi5CQUNLX0VORF9VUkwgPz8gJ2h0dHA6Ly9sb2NhbGhvc3Q6NDAwMCcsXG4gIGNoYW5nZU9yaWdpbjogdHJ1ZSxcbiAgd3MsXG59KVxuXG4vLyBodHRwczovL3ZpdGVqcy5kZXYvY29uZmlnL1xuZXhwb3J0IGRlZmF1bHQgZGVmaW5lQ29uZmlnKHtcbiAgYnVpbGQ6IHtcbiAgICB0YXJnZXQ6IFsnY2hyb21lNTgnXSxcbiAgfSxcblxuICByZXNvbHZlOiB7XG4gICAgYWxpYXM6IHtcbiAgICAgICdAY29tcG9uZW50cyc6IHBhdGgucmVzb2x2ZShfX2Rpcm5hbWUsICcuL3NyYy9wcml2YXRlL2NvbXBvbmVudHMnKSxcbiAgICB9LFxuICAgIGV4dGVuc2lvbnM6IFsnLnRzeCcsICcuanN4JywgJy50cycsICcuanMnLCAnLmpzb24nXSxcbiAgfSxcblxuICBvcHRpbWl6ZURlcHM6IHtcbiAgICBpbmNsdWRlOiBbXG4gICAgICAuLi5kZXBzVG9PcHRpbWl6ZSxcbiAgICAgICdja2VkaXRvcjUtY3VzdG9tLWJ1aWxkL2J1aWxkL2NrZWRpdG9yJyxcbiAgICBdLFxuICB9LFxuXG4gIGN1c3RvbUxvZ2dlcjogbG9nZ2VyLFxuICBcbiAgcGx1Z2luczogW1xuICAgIHZpdGVTdGF0aWNDb3B5KHtcbiAgICAgIHRhcmdldHM6IFtcbiAgICAgICAge1xuICAgICAgICAgIHNyYzogJ3NyYy9zdGF0aWMvZXh0LyonLFxuICAgICAgICAgIGRlc3Q6ICdzdGF0aWMvZXh0J1xuICAgICAgICB9XG4gICAgICBdXG4gICAgfSksXG4gICAge1xuICAgICAgbmFtZTogJ2h0bWwtdHJhbnNmb3JtJyxcbiAgICAgIGVuZm9yY2U6IFwicHJlXCIsXG4gICAgICBhcHBseTogJ3NlcnZlJyxcbiAgICAgIHRyYW5zZm9ybUluZGV4SHRtbChodG1sKSB7XG4gICAgICAgIHJldHVybiBodG1sLnJlcGxhY2UoLyVCQVNFX1BBVEglL2csIGJhc2VQYXRoKVxuICAgICAgICAgIC5yZXBsYWNlKC8lQVBQX1RJVExFJS9nLCBcIk9wZW5DVEkgRGV2XCIpXG4gICAgICAgICAgLnJlcGxhY2UoLyVBUFBfREVTQ1JJUFRJT04lL2csIFwiT3BlbkNUSSBEZXZlbG9wbWVudCBwbGF0Zm9ybVwiKVxuICAgICAgICAgIC5yZXBsYWNlKC8lQVBQX0ZBVklDT04lL2csIGAke2Jhc2VQYXRofS9zdGF0aWMvZXh0L2Zhdmljb24ucG5nYClcbiAgICAgICAgICAucmVwbGFjZSgvJUFQUF9NQU5JRkVTVCUvZywgYCR7YmFzZVBhdGh9L3N0YXRpYy9leHQvbWFuaWZlc3QuanNvbmApXG4gICAgICB9XG4gICAgfSxcbiAgICB7XG4gICAgICBuYW1lOiAndHJlYXQtanMtZmlsZXMtYXMtanN4JyxcbiAgICAgIGFzeW5jIHRyYW5zZm9ybShjb2RlLCBpZCkge1xuICAgICAgICBpZiAoIWlkLm1hdGNoKC9zcmNcXC8uKlxcLmpzJC8pKSByZXR1cm4gbnVsbDtcbiAgICAgICAgLy8gVXNlIHRoZSBleHBvc2VkIHRyYW5zZm9ybSBmcm9tIHZpdGUsIGluc3RlYWQgb2YgZGlyZWN0bHlcbiAgICAgICAgLy8gdHJhbnNmb3JtaW5nIHdpdGggZXNidWlsZFxuICAgICAgICByZXR1cm4gdHJhbnNmb3JtV2l0aEVzYnVpbGQoY29kZSwgaWQsIHtcbiAgICAgICAgICBsb2FkZXI6ICd0c3gnLFxuICAgICAgICAgIGpzeDogJ2F1dG9tYXRpYycsXG4gICAgICAgIH0pO1xuICAgICAgfSxcbiAgICB9LFxuICAgIHJlYWN0KCksXG4gICAgcmVsYXlcbiAgXSxcblxuICBzZXJ2ZXI6IHtcbiAgICBwb3J0OiAzMDAwLFxuICAgIHByb3h5OiB7XG4gICAgICAnL2xvZ291dCc6IGJhY2tQcm94eSgpLFxuICAgICAgJy9zdHJlYW0nOiBiYWNrUHJveHkoKSxcbiAgICAgICcvc3RvcmFnZSc6IGJhY2tQcm94eSgpLFxuICAgICAgJy90YXhpaTInOiBiYWNrUHJveHkoKSxcbiAgICAgICcvZmVlZHMnOiBiYWNrUHJveHkoKSxcbiAgICAgICcvZ3JhcGhxbCc6IGJhY2tQcm94eSh0cnVlKSxcbiAgICAgICcvYXV0aCc6IGJhY2tQcm94eSgpLFxuICAgICAgJy9zdGF0aWMvZmxhZ3MnOiBiYWNrUHJveHkoKSxcbiAgICB9LFxuICB9LFxufSk7XG4iXSwKICAibWFwcGluZ3MiOiAiO0FBQXNhLFNBQVMsY0FBYyxjQUFjLDRCQUE0QjtBQUN2ZSxPQUFPLFdBQVc7QUFDbEIsWUFBWSxVQUFVO0FBQ3RCLE9BQU8sV0FBVztBQUNsQixTQUFTLHNCQUFzQjtBQUovQixJQUFNLG1DQUFtQztBQU96QyxJQUFNLGlCQUFpQjtBQUFBLEVBQ3JCO0FBQUEsRUFDQTtBQUFBLEVBQ0E7QUFBQSxFQUNBO0FBQUEsRUFDQTtBQUFBLEVBQ0E7QUFBQSxFQUNBO0FBQUEsRUFDQTtBQUFBLEVBQ0E7QUFBQSxFQUNBO0FBQUEsRUFDQTtBQUFBLEVBQ0E7QUFBQSxFQUNBO0FBQUEsRUFDQTtBQUFBLEVBQ0E7QUFBQSxFQUNBO0FBQUEsRUFDQTtBQUFBLEVBQ0E7QUFBQSxFQUNBO0FBQUEsRUFDQTtBQUFBLEVBQ0E7QUFBQSxFQUNBO0FBQUEsRUFDQTtBQUFBLEVBQ0E7QUFBQSxFQUNBO0FBQUEsRUFDQTtBQUFBLEVBQ0E7QUFBQSxFQUNBO0FBQUEsRUFDQTtBQUFBLEVBQ0E7QUFBQSxFQUNBO0FBQUEsRUFDQTtBQUFBLEVBQ0E7QUFBQSxFQUNBO0FBQUEsRUFDQTtBQUFBLEVBQ0E7QUFBQSxFQUNBO0FBQUEsRUFDQTtBQUFBLEVBQ0E7QUFBQSxFQUNBO0FBQUEsRUFDQTtBQUFBLEVBQ0E7QUFBQSxFQUNBO0FBQUEsRUFDQTtBQUFBLEVBQ0E7QUFBQSxFQUNBO0FBQUEsRUFDQTtBQUFBLEVBQ0E7QUFBQSxFQUNBO0FBQUEsRUFDQTtBQUFBLEVBQ0E7QUFBQSxFQUNBO0FBQUEsRUFDQTtBQUFBLEVBQ0E7QUFBQSxFQUNBO0FBQUEsRUFDQTtBQUFBLEVBQ0E7QUFBQSxFQUNBO0FBQUEsRUFDQTtBQUFBLEVBQ0E7QUFBQSxFQUNBO0FBQUEsRUFDQTtBQUFBLEVBQ0E7QUFBQSxFQUNBO0FBQUEsRUFDQTtBQUFBLEVBQ0E7QUFBQSxFQUNBO0FBQUEsRUFDQTtBQUFBLEVBQ0E7QUFBQSxFQUNBO0FBQUEsRUFDQTtBQUFBLEVBQ0E7QUFBQSxFQUNBO0FBQUEsRUFDQTtBQUFBLEVBQ0E7QUFBQSxFQUNBO0FBQUEsRUFDQTtBQUFBLEVBQ0E7QUFBQSxFQUNBO0FBQUEsRUFDQTtBQUFBLEVBQ0E7QUFBQSxFQUNBO0FBQUEsRUFDQTtBQUFBLEVBQ0E7QUFBQSxFQUNBO0FBQUEsRUFDQTtBQUFBLEVBQ0E7QUFBQSxFQUNBO0FBQUEsRUFDQTtBQUFBLEVBQ0E7QUFBQSxFQUNBO0FBQUEsRUFDQTtBQUFBLEVBQ0E7QUFBQSxFQUNBO0FBQUEsRUFDQTtBQUFBLEVBQ0E7QUFBQSxFQUNBO0FBQUEsRUFDQTtBQUFBLEVBQ0E7QUFBQSxFQUNBO0FBQUEsRUFDQTtBQUFBLEVBQ0E7QUFBQSxFQUNBO0FBQUEsRUFDQTtBQUFBLEVBQ0E7QUFBQSxFQUNBO0FBQUEsRUFDQTtBQUFBLEVBQ0E7QUFBQSxFQUNBO0FBQUEsRUFDQTtBQUFBLEVBQ0E7QUFBQSxFQUNBO0FBQUEsRUFDQTtBQUFBLEVBQ0E7QUFBQSxFQUNBO0FBQUEsRUFDQTtBQUFBLEVBQ0E7QUFBQSxFQUNBO0FBQUEsRUFDQTtBQUFBLEVBQ0E7QUFBQSxFQUNBO0FBQUEsRUFDQTtBQUFBLEVBQ0E7QUFBQSxFQUNBO0FBQUEsRUFDQTtBQUFBLEVBQ0E7QUFBQSxFQUNBO0FBQUEsRUFDQTtBQUFBLEVBQ0E7QUFBQSxFQUNBO0FBQUEsRUFDQTtBQUFBLEVBQ0E7QUFBQSxFQUNBO0FBQUEsRUFDQTtBQUFBLEVBQ0E7QUFBQSxFQUNBO0FBQUEsRUFDQTtBQUFBLEVBQ0E7QUFBQSxFQUNBO0FBQ0Y7QUFFQSxJQUFNLFNBQVMsYUFBYTtBQUM1QixJQUFNLGNBQWMsT0FBTztBQUUzQixPQUFPLFFBQVEsQ0FBQyxLQUFLLFlBQVk7QUFFL0IsTUFBSSxJQUFJLFNBQVMsbURBQW1EO0FBQUc7QUFDdkUsY0FBWSxLQUFLLE9BQU87QUFDMUI7QUFFQSxJQUFNLFdBQVc7QUFFakIsSUFBTSxZQUFZLENBQUMsS0FBSyxXQUFXO0FBQUEsRUFDakMsUUFBUSxRQUFRLElBQUksZ0JBQWdCO0FBQUEsRUFDcEMsY0FBYztBQUFBLEVBQ2Q7QUFDRjtBQUdBLElBQU8sc0JBQVEsYUFBYTtBQUFBLEVBQzFCLE9BQU87QUFBQSxJQUNMLFFBQVEsQ0FBQyxVQUFVO0FBQUEsRUFDckI7QUFBQSxFQUVBLFNBQVM7QUFBQSxJQUNQLE9BQU87QUFBQSxNQUNMLGVBQW9CLGFBQVEsa0NBQVcsMEJBQTBCO0FBQUEsSUFDbkU7QUFBQSxJQUNBLFlBQVksQ0FBQyxRQUFRLFFBQVEsT0FBTyxPQUFPLE9BQU87QUFBQSxFQUNwRDtBQUFBLEVBRUEsY0FBYztBQUFBLElBQ1osU0FBUztBQUFBLE1BQ1AsR0FBRztBQUFBLE1BQ0g7QUFBQSxJQUNGO0FBQUEsRUFDRjtBQUFBLEVBRUEsY0FBYztBQUFBLEVBRWQsU0FBUztBQUFBLElBQ1AsZUFBZTtBQUFBLE1BQ2IsU0FBUztBQUFBLFFBQ1A7QUFBQSxVQUNFLEtBQUs7QUFBQSxVQUNMLE1BQU07QUFBQSxRQUNSO0FBQUEsTUFDRjtBQUFBLElBQ0YsQ0FBQztBQUFBLElBQ0Q7QUFBQSxNQUNFLE1BQU07QUFBQSxNQUNOLFNBQVM7QUFBQSxNQUNULE9BQU87QUFBQSxNQUNQLG1CQUFtQixNQUFNO0FBQ3ZCLGVBQU8sS0FBSyxRQUFRLGdCQUFnQixRQUFRLEVBQ3pDLFFBQVEsZ0JBQWdCLGFBQWEsRUFDckMsUUFBUSxzQkFBc0IsOEJBQThCLEVBQzVELFFBQVEsa0JBQWtCLEdBQUcsUUFBUSx5QkFBeUIsRUFDOUQsUUFBUSxtQkFBbUIsR0FBRyxRQUFRLDJCQUEyQjtBQUFBLE1BQ3RFO0FBQUEsSUFDRjtBQUFBLElBQ0E7QUFBQSxNQUNFLE1BQU07QUFBQSxNQUNOLE1BQU0sVUFBVSxNQUFNLElBQUk7QUFDeEIsWUFBSSxDQUFDLEdBQUcsTUFBTSxjQUFjO0FBQUcsaUJBQU87QUFHdEMsZUFBTyxxQkFBcUIsTUFBTSxJQUFJO0FBQUEsVUFDcEMsUUFBUTtBQUFBLFVBQ1IsS0FBSztBQUFBLFFBQ1AsQ0FBQztBQUFBLE1BQ0g7QUFBQSxJQUNGO0FBQUEsSUFDQSxNQUFNO0FBQUEsSUFDTjtBQUFBLEVBQ0Y7QUFBQSxFQUVBLFFBQVE7QUFBQSxJQUNOLE1BQU07QUFBQSxJQUNOLE9BQU87QUFBQSxNQUNMLFdBQVcsVUFBVTtBQUFBLE1BQ3JCLFdBQVcsVUFBVTtBQUFBLE1BQ3JCLFlBQVksVUFBVTtBQUFBLE1BQ3RCLFdBQVcsVUFBVTtBQUFBLE1BQ3JCLFVBQVUsVUFBVTtBQUFBLE1BQ3BCLFlBQVksVUFBVSxJQUFJO0FBQUEsTUFDMUIsU0FBUyxVQUFVO0FBQUEsTUFDbkIsaUJBQWlCLFVBQVU7QUFBQSxJQUM3QjtBQUFBLEVBQ0Y7QUFDRixDQUFDOyIsCiAgIm5hbWVzIjogW10KfQo=
