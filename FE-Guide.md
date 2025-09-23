# OpenCTI Frontend Development Guide

## Table of Contents
1. [Project Structure](#project-structure)
2. [Getting Started](#getting-started)
3. [Project Overview](#project-overview)
4. [Theme Customization & Branding](#theme-customization--branding)
5. [Navigation Components](#navigation-components)
6. [Table Customizations in Internal Pages](#table-customizations-in-internal-pages)
7. [Loader System & Lazy Loading Implementation](#loader-system--lazy-loading-implementation)
8. [Dashboard Components](#dashboard-components)
9. [Component Customization](#component-customization)
10. [Internal Page Structure - Threats Example](#internal-page-structure---threats-example)

## Project Structure

```
src/
├── components/          # Shared UI components
│   ├── ThemeDark.ts    # Main theme configuration
│   ├── Loader.tsx      # Loading components
│   └── ...
├── private/            # Private application components
│   ├── components/     # Main application components
│   │   ├── Dashboard.jsx           # Main dashboard
│   │   ├── common/                 # Shared dashboard components
│   │   │   ├── stix_relationships/ # Chart components
│   │   │   ├── stix_core_objects/  # Data display components
│   │   │   └── location/           # Map components
│   │   └── ...
│   └── nav/           # Navigation components
│       ├── LeftBar.jsx    # Sidebar navigation
│       └── TopBar.tsx     # Top navigation bar
├── static/            # Static assets
│   └── images/        # Logo and image files
│       ├── logo_text_dark.webp
│       ├── logo_dark2.ico
│       └── ...
├── utils/             # Utility functions and hooks
├── relay/             # GraphQL Relay configuration
└── ...
```

## Getting Started

### Prerequisites
- Node.js (version 20 or higher)
- Yarn package manager
- Git

### Installation & Setup

1. **Clone the Repository**
   ```bash
   git clone <repository-url>
   cd opencti-front
   ```

2. **Install Dependencies**
   ```bash
   yarn install
   ```

3. **Start Development Server**
   ```bash
   yarn dev
   ```

4. **Build for Production**
   ```bash
   yarn build
   ```

### Available Scripts

- `yarn dev` - Start development server with hot reload
- `yarn build` - Build for production
- `yarn lint` - Run ESLint for code quality
- `yarn test` - Run test suite
- `yarn relay` - Compile GraphQL Relay queries

## Project Overview

This OpenCTI instance has been completely customized with a custom theme and branding system. The entire color scheme, logos, and visual identity have been transformed to match a custom brand identity.

### Key Features
- **Custom Dark Theme**: Sophisticated color palette with brand-specific colors
- **Responsive Design**: Adapts to different screen sizes and devices
- **Material-UI Integration**: Extensive component customization and theming
- **Dashboard Analytics**: Rich data visualization components
- **Navigation System**: Collapsible sidebar and top navigation bar

### Technology Stack
- **React 19.0.0** - Frontend framework
- **Material-UI 6.5.0** - UI component library
- **Relay 20.0.0** - GraphQL client
- **Vite 6.3.5** - Build tool and dev server
- **TypeScript** - Type safety and development experience

## Theme Customization & Branding

### Custom Color Scheme

The project uses a sophisticated dark theme with the following custom color palette:

**Primary Colors:**
- **Primary**: `#871719` (Deep burgundy red)
- **Background**: `#111322` (Dark navy blue)
- **Paper/Cards**: `#111322` (Matching background)
- **Navigation**: `#111322` (Consistent dark theme)

**Accent Colors:**
- **AI Features**: `#9575cd` (Purple for AI components)
- **Danger Zone**: `#f6685e` (Red for destructive actions)

### Custom Branding & Logos

**Logo System:**
- **Main Logo**: Custom logo with dark theme variant
- **Collapsed Logo**: Icon-only version for sidebar
- **File Locations**:
  - `src/static/images/logo_text_dark.webp` - Main logo
  - `src/static/images/logo_dark2.ico` - Collapsed logo
  - `src/static/images/logo_text_white.png` - White variant

**Theme Configuration:**
- **File**: `src/components/ThemeDark.ts`
- **Customizable Parameters**:
  - `logo` - Main application logo
  - `logo_collapsed` - Sidebar collapsed logo
  - `background` - Main background color
  - `paper` - Card/paper background color
  - `nav` - Navigation background color
  - `primary` - Primary brand color
  - `secondary` - Secondary accent color
  - `accent` - Additional accent color

### Advanced Styling Features

**Dashboard-Specific Gradients:**
- Custom gradient backgrounds for dashboard components
- Linear gradient: `135deg, #1c1436 0%, #060311 50%, #030308 100%`
- Applied specifically to dashboard pages for enhanced visual appeal

**Component Customizations:**
- **Border Radius**: 16px for modern, rounded appearance
- **Typography**: Inter font family throughout
- **Table Styling**: Custom spacing and hover effects
- **Button Styling**: Custom outlined and icon button variants
- **Tooltip Styling**: Dark theme with custom opacity

**Responsive Design:**
- Theme adapts to different screen sizes
- Consistent color application across all components
- Custom scrollbar styling matching the theme

### Implementation Details

The theme system is built on Material-UI's theming capabilities with extensive customizations:

1. **Theme Provider**: Wraps the entire application
2. **Color Palette**: Completely customized with brand colors
3. **Component Overrides**: Extensive MUI component styling
4. **CSS-in-JS**: Advanced styling with theme-aware properties
5. **Dynamic Theming**: Support for runtime theme changes

### Customization Guide: Changing Logos and Colors

To modify the theme colors and logos, developers need to work with the following key files and locations:

#### Logo Files Location
**Main Directory**: `src/static/images/`

**Logo Files to Replace:**
- `logo_text_dark.webp` - Main application logo (expanded sidebar)
- `logo_dark2.ico` - Collapsed sidebar logo (icon only)
- `logo_text_white.png` - White variant logo (for light backgrounds)
- `logo_text_dark.png` - Alternative dark logo format

**Logo Specifications:**
- **Main Logo**: Recommended size 200x60px, WebP format preferred
- **Collapsed Logo**: Recommended size 32x32px, ICO format
- **Format Support**: WebP, PNG, ICO formats supported

#### Color Configuration Files

**Primary Theme File**: `src/components/ThemeDark.ts`

**Key Color Constants to Modify:**
```typescript
// Lines 14-19 in ThemeDark.ts
export const THEME_DARK_DEFAULT_BACKGROUND = '#111322';
const THEME_DARK_DEFAULT_PRIMARY = '#871719';
const THEME_DARK_DEFAULT_ACCENT = '#111322';
const THEME_DARK_DEFAULT_PAPER = '#111322';
const THEME_DARK_DEFAULT_NAV = '#111322';
```

**Color Customization Steps:**
1. **Update Constants**: Modify the color constants at the top of `ThemeDark.ts`
2. **Test Changes**: Run the development server to see immediate changes
3. **Verify Contrast**: Ensure accessibility compliance with color combinations
4. **Update Gradients**: Modify dashboard-specific gradients if needed (lines 225-230)

#### Advanced Color Customization

**Dashboard-Specific Gradients** (Lines 225-230):
```typescript
'.dashboard-page .MuiPaper-root': {
  background: 'linear-gradient(135deg, #1c1436 0%, #060311 50%, #030308 100%) !important',
  borderRadius: 16,
},
```

#### Logo Integration Points

**Theme Integration** (Lines 31-32):
```typescript
logo: logo || fileUri(LogoText),
logo_collapsed: logo_collapsed || fileUri(LogoCollapsed),
```

**File Path Configuration** (Lines 11-12):
```typescript
const LogoText = '/static/images/logo_text_dark.webp';
const LogoCollapsed = '/static/images/logo_dark2.ico';
```

#### Step-by-Step Customization Process

1. **Replace Logo Files**:
   - Navigate to `src/static/images/`
   - Replace existing logo files with your custom versions
   - Maintain the same filenames or update the constants in `ThemeDark.ts`

2. **Update Color Scheme**:
   - Open `src/components/ThemeDark.ts`
   - Modify the color constants (lines 14-19)
   - Update any component-specific colors as needed

3. **Test Changes**:
   - Run `yarn dev` to start the development server
   - Navigate through different pages to verify color consistency
   - Check both expanded and collapsed sidebar states

4. **Build and Deploy**:
   - Run `yarn build` to create production build
   - Verify changes in production environment

#### Additional Customization Files

**Typography**: `src/components/ThemeDark.ts` (lines 73-133)
- Font family: Inter (line 74)
- Font sizes and weights for different text elements

**Component Styling**: `src/components/ThemeDark.ts` (lines 134-422)
- Material-UI component overrides
- Custom button styles, tooltips, and form controls

**CSS Variables**: Any additional custom CSS can be added to the `MuiCssBaseline` section (lines 214-394)

## Navigation Components

### Sidebar (LeftBar)

The main sidebar navigation is located at:
```
src/private/components/nav/LeftBar.jsx
```

**Key Features:**
- **Collapsible Navigation** - Can be expanded/collapsed with toggle functionality
- **Menu Categories** - Organized into main sections:
  - Analyses
  - Cases  
  - Events
  - Observations
  - Threats
  - Arsenal
  - Techniques
  - Entities
  - Locations
  - Dashboards
  - Investigations
  - Data
  - Settings

**Customization Options:**
- `submenu_auto_collapse` - Auto-collapse submenus when opening new ones
- `submenu_show_icons` - Show/hide icons in submenu items
- `navOpen` - Controls sidebar expanded/collapsed state
- `selectedMenu` - Tracks which menu items are currently selected

**Styling:**
- Uses Material-UI `Drawer` component with permanent variant
- Responsive width: `OPEN_BAR_WIDTH` (expanded) / `SMALL_BAR_WIDTH` (collapsed)
- Dark theme with custom background colors
- Smooth transitions for expand/collapse animations

### TopBar

The top navigation bar is located at:
```
src/private/components/nav/TopBar.tsx
```

**Key Features:**
- **Search Functionality** - Global search input with keyword and filter support
- **User Menu** - Account access, notifications, and user settings
- **Draft Context Banner** - Shows when in draft mode
- **Logo/Branding** - Platform logo with theme-aware variants
- **Notifications** - Real-time notification system

**Integration:**
- Works in conjunction with LeftBar for complete navigation
- Responsive to LeftBar width changes
- Handles search routing and filtering

### Adding/Removing Pages in LeftBar

To add or remove pages from the sidebar navigation, developers need to modify the `LeftBar.jsx` file:

**File Location**: `src/private/components/nav/LeftBar.jsx`

#### Menu Structure

The LeftBar uses a `generateSubMenu` function to create menu sections. Each menu section contains an array of menu entries with the following structure:

```javascript
{
  type: 'EntityType',           // Entity type for filtering
  link: '/dashboard/path',      // Route path
  label: 'Menu Label',          // Display text
  icon: <IconComponent />,      // Material-UI icon
  granted: permissionCheck,     // Permission requirement (optional)
  exact: true                   // Exact route matching (optional)
}
```

#### Current Menu Sections

**Analyses Section** (Lines 666-675):
```javascript
generateSubMenu('analyses', [
  { type: 'Report', link: '/dashboard/analyses/reports', label: 'Reports', icon: <DescriptionOutlined fontSize="small" /> },
  // Commented out entries can be uncommented to add them back
])
```

**Observations Section** (Lines 723-731):
```javascript
generateSubMenu('observations', [
  { type: 'Stix-Cyber-Observable', link: '/dashboard/observations/observables', label: 'Observables', icon: <LanguageOutlined fontSize="small" /> },
  { type: 'Indicator', link: '/dashboard/observations/indicators', label: 'Indicators', icon: <ShieldSearch fontSize="small" /> },
])
```

**Threats Section** (Lines 781-794):
```javascript
generateSubMenu('threats', [
  { type: 'Intrusion-Set', link: '/dashboard/threats/intrusion_sets', label: 'Intrusion sets', icon: <ComputerOutlined fontSize="small" /> },
  { type: 'Campaign', link: '/dashboard/threats/campaigns', label: 'Campaigns', icon: <TrackChanges fontSize="small" /> },
])
```

**Arsenal Section** (Lines 842-850):
```javascript
generateSubMenu('arsenal', [
  { type: 'Malware', link: '/dashboard/arsenal/malwares', label: 'Malwares', icon: <Biohazard fontSize="small" /> },
  { type: 'Tool', link: '/dashboard/arsenal/tools', label: 'Tools', icon: <WebAssetOutlined fontSize="small" /> },
  { type: 'Vulnerability', link: '/dashboard/arsenal/vulnerabilities', label: 'Vulnerabilities', icon: <LockOutlined fontSize="small" /> },
])
```

**Techniques Section** (Lines 898-907):
```javascript
generateSubMenu('techniques', [
  { type: 'Attack-Pattern', link: '/dashboard/techniques/attack_patterns', label: 'Attack patterns', icon: <LockPattern fontSize="small" /> },
  { type: 'Course-Of-Action', link: '/dashboard/techniques/courses_of_action', label: 'Courses of action', icon: <ProgressWrench fontSize="small" /> },
  { type: 'Data-Component', link: '/dashboard/techniques/data_components', label: 'Data components', icon: <SourceOutlined fontSize="small" /> },
  { type: 'Data-Source', link: '/dashboard/techniques/data_sources', label: 'Data sources', icon: <Database fontSize="small" /> },
])
```

**Entities Section** (Lines 955-965):
```javascript
generateSubMenu('entities', [
  { type: 'Sector', link: '/dashboard/entities/sectors', label: 'Sectors', icon: <DomainOutlined fontSize="small" /> },
  { type: 'Organization', link: '/dashboard/entities/organizations', label: 'Organizations', icon: <AccountBalanceOutlined fontSize="small" /> },
  { type: 'SecurityPlatform', link: '/dashboard/entities/security_platforms', label: 'Security platforms', icon: <SecurityOutlined fontSize="small" /> },
  { type: 'System', link: '/dashboard/entities/systems', label: 'Systems', icon: <StorageOutlined fontSize="small" /> },
  { type: 'Individual', link: '/dashboard/entities/individuals', label: 'Individuals', icon: <PersonOutlined fontSize="small" /> },
])
```

**Locations Section** (Lines 1013-1022):
```javascript
generateSubMenu('locations', [
  { type: 'Country', link: '/dashboard/locations/countries', label: 'Countries', icon: <FlagOutlined fontSize="small" /> },
  // Other location types are commented out
])
```

#### How to Add a New Page

1. **Add Menu Entry**: Add a new object to the appropriate `generateSubMenu` array:
   ```javascript
   { type: 'NewEntity', link: '/dashboard/section/new_entity', label: 'New Entity', icon: <NewIcon fontSize="small" /> }
   ```

2. **Import Icon**: Add the required icon import at the top of the file (lines 11-85)

3. **Add Route**: Ensure the corresponding route exists in the application routing

4. **Add Permission Check** (if needed): Add permission requirements:
   ```javascript
   { type: 'NewEntity', link: '/dashboard/section/new_entity', label: 'New Entity', icon: <NewIcon fontSize="small" />, granted: isGrantedToNewEntity }
   ```

#### How to Remove a Page

1. **Comment Out Entry**: Comment out the menu entry in the appropriate `generateSubMenu` array
2. **Or Remove Entirely**: Delete the entry from the array

#### How to Add a New Section

1. **Add Section Header**: Create a new section with header styling (similar to existing sections)
2. **Add generateSubMenu Call**: Add a new `generateSubMenu` call with your menu entries
3. **Add Security Wrapper**: Wrap in appropriate `<Security>` component if needed
4. **Add Divider**: Add visual separator if needed

#### Hidden/Commented Sections

Several sections are currently commented out and can be enabled:
- **Data Section** (Lines 1027-1063) - Contains entities, relationships, ingestion, import, processing, sharing
- **Settings Section** (Lines 1107-1148) - Contains parameters, security, customization, taxonomies, activity, file indexing, support
- **Trash Section** (Lines 1064-1090) - For deleted items management

To enable these sections, simply uncomment the relevant code blocks.

## Table Customizations in Internal Pages

The OpenCTI platform includes comprehensive table customization features that allow users to show/hide columns, reorder them, and adjust their widths. This system is implemented across all internal data tables.

### Core Table System Files

**Main DataTable Component**: `src/components/dataGrid/DataTable.tsx`
- Central component that wraps all table functionality
- Handles data fetching, pagination, and column management

**DataTable Component Logic**: `src/components/dataGrid/components/DataTableComponent.tsx`
- Core table logic and column building
- Local storage integration for column preferences
- Column visibility and ordering management

**Table Headers**: `src/components/dataGrid/components/DataTableHeaders.tsx`
- Header rendering and column menu implementation
- Drag-and-drop column reordering
- Column visibility toggle functionality

**Individual Header**: `src/components/dataGrid/components/DataTableHeader.tsx`
- Individual column header rendering
- Sort functionality and column menu triggers

### Table Customization Features

#### 1. Column Visibility Toggle
Users can show/hide columns through the column menu:

**Implementation Location**: `src/components/dataGrid/components/DataTableHeaders.tsx` (Lines 146-149)

```javascript
<Checkbox
  onClick={() => handleToggleVisibility(c.id)}
  checked={c.visible}
/>
```

**How it works**:
- Click the three-dot menu (⋮) on any column header
- Select/deselect columns from the dropdown menu
- Changes are saved to localStorage automatically

#### 2. Column Reordering (Drag & Drop)
Users can reorder columns by dragging them:

**Implementation Location**: `src/components/dataGrid/components/DataTableHeaders.tsx` (Lines 111-128)

```javascript
<DragDropContext
  onDragEnd={({ source, destination }) => {
    const result = Array.from(draggableColumns);
    const [removed] = result.splice(source.index, 1);
    result.splice(destination.index, 0, removed);
    // Update column order
  }}
>
```

**How it works**:
- Open the column menu (⋮) on any header
- Drag columns up/down in the menu list
- Order is saved automatically

#### 3. Column Width Adjustment
Users can resize columns by dragging column borders:

**Implementation Location**: `src/components/dataGrid/components/DataTableHeader.tsx` (Lines 103-109)

```javascript
const cellWidth = Math.round(tableWidth * (column.percentWidth / 100));
// Column resizing logic with resize handles
```

**How it works**:
- Hover over column borders to see resize cursor
- Drag to adjust column width
- Widths are saved as percentages

#### 4. Local Storage Persistence
All column customizations are automatically saved:

**Implementation Location**: `src/components/dataGrid/components/DataTableComponent.tsx` (Lines 75-76)

```javascript
const columnsLocalStorage = useDataTableLocalStorage<LocalStorageColumns>(`${storageKey}_columns`, {}, true);
const [localStorageColumns, setLocalStorageColumns] = columnsLocalStorage;
```

**Storage Structure**:
```javascript
{
  "column_name": {
    "index": 0,           // Column order
    "visible": true,      // Column visibility
    "percentWidth": 25    // Column width percentage
  }
}
```

### How to Remove Columns from Tables

#### Method 1: Hide Columns in dataColumns Definition

**File Examples**:
- **Reports Table**: `src/private/components/analyses/Reports.tsx` (Lines 184-204)
- **Indicators Table**: `src/private/components/observations/Indicators.tsx` (Lines 159-179)
- **Observables Table**: `src/private/components/observations/StixCyberObservables.tsx` (Lines 75-95)

**Example - Hiding a column in Reports table**:
```javascript
const dataColumns: DataTableProps['dataColumns'] = {
  name: {
    percentWidth: 25,
    isSortable: true,
  },
  // report_types: {},  // Comment out to hide this column
  createdBy: {
    percentWidth: 12,
    isSortable: isRuntimeSort,
  },
  // creator: {         // Comment out to hide this column
  //   percentWidth: 12,
  //   isSortable: isRuntimeSort,
  // },
};
```

#### Method 2: Remove Columns from Fragment Queries

**File Location**: GraphQL fragment files (e.g., `src/private/components/analyses/Reports.tsx`)

**Example - Removing a field from the GraphQL query**:
```javascript
const reportLineFragment = graphql`
  fragment ReportLine_node on Report {
    id
    name
    # report_types  # Comment out to remove from query
    createdBy {
      ... on Identity {
        name
      }
    }
    # creator {     # Comment out to remove from query
    #   name
    # }
  }
`;
```

#### Method 3: Modify Column Rendering Logic

**File Location**: Line component files (e.g., `src/private/components/analyses/ReportLine.tsx`)

**Example - Conditionally hide column rendering**:
```javascript
const ReportLine = ({ data, dataColumns }) => {
  return (
    <TableRow>
      <TableCell>{data.name}</TableCell>
      {/* {dataColumns.report_types && (
        <TableCell>{data.report_types}</TableCell>
      )} */}
      <TableCell>{data.createdBy?.name}</TableCell>
    </TableRow>
  );
};
```

### Custom Column Widths

**Example - Setting custom column widths**:
```javascript
const dataColumns = {
  name: {
    percentWidth: 30,        // 30% of table width
    isSortable: true,
  },
  createdBy: {
    percentWidth: 15,        // 15% of table width
    isSortable: false,
  },
  created: {
    percentWidth: 20,        // 20% of table width
    isSortable: true,
  },
};
```

### Table Customization Examples

#### Reports Table Customization
**File**: `src/private/components/analyses/Reports.tsx`

**Current Columns**:
- Name (25%)
- Report Types
- Created By (12%)
- Creator (commented out)
- Created (12%)
- Modified (12%)

#### Indicators Table Customization
**File**: `src/private/components/observations/Indicators.tsx`

**Current Columns**:
- Pattern Type (13%)
- Name (28%)
- Created By (14%)
- Object Label (14%)
- Created (14%)
- Modified (14%)

#### Observables Table Customization
**File**: `src/private/components/observations/StixCyberObservables.tsx`

**Current Columns**:
- Entity Type (13%)
- Observable Value (33%)
- Created By (14%)
- Object Label (14%)
- Created (14%)
- Modified (14%)

### Advanced Customization

#### Custom Column Labels
```javascript
const dataColumns = {
  observable_value: {
    label: 'Representation',  // Custom label instead of default
    percentWidth: 33,
    isSortable: true,
  },
};
```

#### Conditional Column Visibility
```javascript
const dataColumns = {
  name: {
    percentWidth: 25,
    isSortable: true,
  },
  // Only show if user has specific permissions
  ...(userHasPermission ? {
    sensitive_data: {
      percentWidth: 15,
      isSortable: false,
    }
  } : {}),
};
```

#### Runtime Sort Configuration
```javascript
const dataColumns = {
  createdBy: {
    isSortable: isRuntimeSort ?? false,  // Dynamic sort capability
    percentWidth: 14,
  },
};
```

## Loader System & Lazy Loading Implementation

The OpenCTI platform features a sophisticated loader system with custom Zerowl branding and comprehensive lazy loading implementation for optimal performance.

### Main Loader Component

**File Location**: `src/components/Loader.tsx`

The main loader component provides a branded loading experience with your custom Zerowl icon and sophisticated animations.

#### Loader Variants

The loader supports three different variants for different use cases:

```typescript
export enum LoaderVariant {
  container = 'container',    // Full page loader
  inElement = 'inElement',    // In-component loader
  inline = 'inline',          // Small inline loader
}
```

#### Custom Zerowl Branding

**Logo Integration**:
- **Logo File**: `src/static/images/logo-icon.png` - Your custom Zerowl icon
- **Logo Size**: 60x80px for container variant, 48x48px for inElement variant
- **Logo Effects**: Custom filter with brightness, invert, and drop-shadow effects

**Visual Design**:
```typescript
logo: {
  width: 60,
  height: 80,
  userSelect: 'none',
  filter: 'brightness(0) invert(1) drop-shadow(0 0 15px rgba(9, 63, 49, 0.8)) drop-shadow(0 0 25px rgba(9, 63, 49, 0.5))',
  animation: '$scaleInOut 2.5s ease-in-out infinite',
}
```

#### Animation System

**1. Spinning Ring Animation**:
```typescript
'@keyframes spin': {
  from: { transform: 'rotate(0deg)' },
  to: { transform: 'rotate(360deg)' },
}

ring: {
  position: 'absolute',
  inset: 0,
  borderRadius: '9999px',
  border: '3px solid transparent',
  borderBottomColor: '#ef4444',  // Red accent color
  animation: '$spin 1s linear infinite',
  willChange: 'transform',
}
```

**2. Logo Scale Animation**:
- The logo has a subtle scale-in-out animation
- Creates a breathing effect while maintaining the spinning ring
- 2.5-second ease-in-out infinite cycle

**3. Layered Design**:
- **Ring Frame**: Non-rotating container (128x128px)
- **Spinning Ring**: Absolute positioned rotating border
- **Static Logo**: Centered logo that doesn't rotate
- **Text Container**: Optional heading and subheading

#### Loader Usage Examples

**1. Full Page Loader (Container Variant)**:
```javascript
<Loader 
  variant={LoaderVariant.container}
  heading="Loading Dashboard"
  subheading="Please wait while we load your data"
/>
```

**2. Component Loader (InElement Variant)**:
```javascript
<Loader 
  variant={LoaderVariant.inElement}
  withRightPadding={true}
  withTopMargin={true}
/>
```

**3. Inline Loader (Inline Variant)**:
```javascript
<Loader variant={LoaderVariant.inline} />
```

### Lazy Loading Implementation

The platform implements comprehensive lazy loading for optimal performance and code splitting.

#### 1. Component-Level Lazy Loading

**Threats Section Example** (`src/private/components/threats/Root.tsx`):

```javascript
// Lazy load all threat components
const ThreatActorsGroup = lazy(() => import('./ThreatActorsGroup'));
const IntrusionSets = lazy(() => import('./IntrusionSets'));
const Campaigns = lazy(() => import('./Campaigns'));
const ThreatActorsIndividual = lazy(() => import('./ThreatActorsIndividual'));

// Lazy load individual entity components
const RootThreatActorGroup = lazy(() => import('./threat_actors_group/Root'));
const RootIntrusionSet = lazy(() => import('./intrusion_sets/Root'));
const RootCampaign = lazy(() => import('./campaigns/Root'));
const RootThreatActorIndividual = lazy(() => import('./threat_actors_individual/Root'));
```

#### 2. Suspense Integration with Custom Loader

**Entity Detail Pages** (`src/private/components/threats/campaigns/Root.tsx`):

```javascript
const Root = () => {
  const { campaignId } = useParams() as { campaignId: string; };
  const queryRef = useQueryLoading<RootCampaignQuery>(campaignQuery, {
    id: campaignId,
  });

  return (
    <>
      {queryRef && (
        <Suspense fallback={<Loader variant={LoaderVariant.container} />}>
          <RootCampaign queryRef={queryRef} campaignId={campaignId} />
        </Suspense>
      )}
    </>
  );
};
```

#### 3. Query Loading Integration

**GraphQL Query Loading**:
```javascript
const queryRef = useQueryLoading<CampaignsCardsPaginationQuery>(
  campaignsCardsQuery,
  queryPaginationOptions,
);

// Conditional rendering with loader
{queryRef && (
  <React.Suspense
    fallback={
      <Grid container={true} spacing={3} style={{ paddingLeft: 17 }}>
        {Array(20)
          .fill(0)
          .map((_, idx) => (
            <Grid item xs={3} key={idx}>
              <GenericAttackCardDummy />
            </Grid>
          ))}
      </Grid>
    }
  >
    <CampaignsCards
      queryRef={queryRef}
      setNumberOfElements={helpers.handleSetNumberOfElements}
      onLabelClick={helpers.handleAddFilter}
    />
  </React.Suspense>
)}
```

#### 4. Dashboard Loading

**Main Dashboard** (`src/private/components/Dashboard.jsx`):

```javascript
const Dashboard = () => {
  const queryRef = useQueryLoading(dashboardQuery, {});
  return (
    <>
      {queryRef && (
        <React.Suspense fallback={<div />}>
          <DashboardComponent queryRef={queryRef} />
        </React.Suspense>
      )}
    </>
  );
};
```

### Loading States Hierarchy

#### 1. Page-Level Loading
- **Full Page Reload**: Custom Zerowl loader with spinning ring and logo
- **Route Navigation**: Suspense with container variant loader
- **GraphQL Queries**: Query loading with conditional rendering

#### 2. Component-Level Loading
- **Entity Details**: Container variant loader for individual entity pages
- **List Components**: Skeleton loaders or dummy components
- **Data Tables**: Inline loaders for table operations

#### 3. Inline Loading
- **Button Actions**: Inline variant for form submissions
- **Table Operations**: Small inline loaders for sorting/filtering
- **Real-time Updates**: Minimal loading indicators

### Performance Benefits

#### 1. Code Splitting
- **Route-based Splitting**: Each major section loads independently
- **Component Splitting**: Individual entity types load on-demand
- **Feature Splitting**: Advanced features load only when needed

#### 2. Bundle Optimization
- **Reduced Initial Bundle**: Only essential code loads initially
- **Lazy Imports**: Components load when actually needed
- **Tree Shaking**: Unused code is eliminated from bundles

#### 3. User Experience
- **Branded Loading**: Consistent Zerowl branding throughout
- **Progressive Loading**: Content appears as it becomes available
- **Smooth Transitions**: Seamless loading state transitions

### Customization Options

#### 1. Loader Styling
```typescript
// Customize colors
borderBottomColor: '#ef4444',  // Ring color
color: '#ffffff',              // Text color
color: 'rgba(255,255,255,0.7)' // Subtext color

// Customize animations
animation: '$spin 1s linear infinite',           // Ring speed
animation: '$scaleInOut 2.5s ease-in-out infinite', // Logo animation
```

#### 2. Loader Content
```javascript
<Loader 
  heading="Custom Loading Message"
  subheading="Custom subheading text"
  variant={LoaderVariant.container}
/>
```

#### 3. Loader Positioning
```javascript
<Loader 
  variant={LoaderVariant.inElement}
  withRightPadding={true}    // Account for sidebar
  withTopMargin={true}       // Account for header
/>
```

### Implementation Best Practices

#### 1. Consistent Usage
- Always use the custom Loader component for branded experience
- Choose appropriate variant for the context
- Provide meaningful loading messages

#### 2. Performance Optimization
- Use lazy loading for non-critical components
- Implement proper Suspense boundaries
- Combine with skeleton loaders for better UX

#### 3. Error Handling
- Combine with error boundaries
- Provide fallback content for failed loads
- Handle network errors gracefully

## Dashboard Components

### File Location
The main dashboard component can be found at:
```
src/private/components/Dashboard.jsx
```

This file contains the primary dashboard implementation for the OpenCTI frontend application.

### Dashboard Components

The dashboard utilizes several key components to display threat intelligence data:

#### Chart Components
- **StixRelationshipsMultiAreaChart** - Displays relationship data over time in an area chart format
- **StixRelationshipsHorizontalBars** - Shows horizontal bar charts for threat activity, victims, and labels
- **StixRelationshipsDonut** - Renders donut charts for malware activity distribution
- **StixRelationshipsDistributionList** - Displays distribution lists for vulnerabilities

#### Data Display Components
- **StixCoreObjectsNumber** - Shows numerical counts for different entity types (Intrusion Sets, Malwares, Reports, Indicators)
- **StixCoreObjectsList** - Displays lists of STIX core objects (e.g., latest reports)
- **SimpleWorldMap** - Renders world map visualization for targeted countries

#### UI Components
- **Card** - Material-UI card components for organizing dashboard sections
- **Grid** - Material-UI grid system for layout management
- **Paper** - Material-UI paper component for elevated content areas
- **Suspense** - React Suspense for lazy loading and fallback handling
- **SkeletonLoader** - Custom skeleton loader for loading states

#### Security & Context Components
- **Security** - Handles access control and permissions
- **UserContext** - Provides user context throughout the dashboard

### Data Selection Configuration

All components use a `dataSelection` prop that accepts an array of configuration objects with the following structure:

```javascript
dataSelection: [
  {
    attribute: "internal_id",           // Field to aggregate
    isTo: true,                        // Direction of relationship
    number: 10,                        // Number of items to show
    filters: {                         // Filter configuration
      mode: "and",
      filters: [
        {
          key: "entity_type",
          values: ["Report"]
        }
      ],
      filterGroups: []
    },
    date_attribute: "created_at",      // Date field for time-based queries
    sort_by: "created_at",            // Sort field
    sort_mode: "desc",                // Sort direction
    columns: [...]                    // Column configuration for lists
  }
]
```

## Component Customization

Each dashboard component offers various customization options through props:

### StixRelationshipsMultiAreaChart
**Props:**
- `title` - Chart title (string)
- `height` - Chart height (number)
- `startDate` - Start date for data (DateTime)
- `endDate` - End date for data (DateTime)
- `dataSelection` - Array of data selection configurations
- `parameters` - Additional parameters object:
  - `interval` - Time interval (e.g., 'day', 'month')
  - `stacked` - Boolean for stacked area chart
  - `legend` - Boolean to show/hide legend
- `withExportPopover` - Boolean to enable export functionality
- `isReadOnly` - Boolean for read-only mode
- `variant` - Visual variant styling

### StixRelationshipsHorizontalBars
**Props:**
- `title` - Chart title (string)
- `height` - Chart height (number)
- `startDate` - Start date for data (DateTime)
- `endDate` - End date for data (DateTime)
- `dataSelection` - Array of data selection configurations
- `customColors` - Array of custom colors for bars
- `parameters` - Additional parameters object:
  - `distributed` - Boolean for distributed layout
  - `number` - Number of items to display
- `withoutTitle` - Boolean to hide title
- `withExportPopover` - Boolean to enable export functionality
- `isReadOnly` - Boolean for read-only mode
- `variant` - Visual variant styling

### StixRelationshipsDonut
**Props:**
- `title` - Chart title (string)
- `height` - Chart height (number)
- `startDate` - Start date for data (DateTime)
- `endDate` - End date for data (DateTime)
- `dataSelection` - Array of data selection configurations
- `field` - Field to group data by
- `parameters` - Additional parameters object
- `withExportPopover` - Boolean to enable export functionality
- `isReadOnly` - Boolean for read-only mode
- `variant` - Visual variant styling

### StixRelationshipsDistributionList
**Props:**
- `title` - List title (string)
- `height` - List height (number)
- `startDate` - Start date for data (DateTime)
- `endDate` - End date for data (DateTime)
- `dataSelection` - Array of data selection configurations
- `overflow` - Overflow handling (string)
- `field` - Field to group data by
- `parameters` - Additional parameters object
- `variant` - Visual variant styling

### StixCoreObjectsNumber
**Props:**
- `height` - Component height (number)
- `startDate` - Start date for data (DateTime)
- `endDate` - End date for data (DateTime)
- `dataSelection` - Array of data selection configurations
- `withoutTitle` - Boolean to hide title
- `parameters` - Additional parameters object:
  - `title` - Custom title override
- `variant` - Visual variant styling

### StixCoreObjectsList
**Props:**
- `title` - List title (string)
- `height` - List height (number)
- `startDate` - Start date for data (DateTime)
- `endDate` - End date for data (DateTime)
- `dataSelection` - Array of data selection configurations
- `widgetId` - Unique widget identifier
- `parameters` - Additional parameters object:
  - `title` - Custom title override
- `variant` - Visual variant styling

### SimpleWorldMap
**Props:**
- `serverList` - Array of country data objects
- `height` - Map height (number)

## Internal Page Structure - Threats Example

The threats section provides an excellent example of how internal pages are structured in OpenCTI. This section demonstrates the complete architecture from routing to individual entity management.

### Threats Folder Structure

**Main Directory**: `src/private/components/threats/`

```
threats/
├── Root.tsx                    # Main routing component
├── Campaigns.tsx              # Campaigns list page
├── IntrusionSets.tsx          # Intrusion Sets list page
├── ThreatActorsGroup.tsx      # Threat Actors Group list page
├── ThreatActorsIndividual.tsx # Threat Actors Individual list page
├── campaigns/                 # Campaign-specific components
│   ├── Root.tsx              # Campaign detail routing
│   ├── Campaign.tsx          # Campaign overview component
│   ├── CampaignCard.tsx      # Campaign card component
│   ├── CampaignCreation.tsx  # Campaign creation form
│   ├── CampaignDetails.jsx   # Campaign details view
│   ├── CampaignEdition.jsx   # Campaign editing form
│   └── __generated__/        # GraphQL generated files
├── intrusion_sets/            # Intrusion Set-specific components
│   ├── Root.tsx              # Intrusion Set detail routing
│   ├── IntrusionSet.tsx      # Intrusion Set overview component
│   ├── IntrusionSetCard.tsx  # Intrusion Set card component
│   ├── IntrusionSetCreation.tsx # Intrusion Set creation form
│   ├── IntrusionSetDetails.tsx  # Intrusion Set details view
│   ├── IntrusionSetEdition.jsx  # Intrusion Set editing form
│   └── __generated__/        # GraphQL generated files
└── threat_actors_group/       # Threat Actor Group components
    └── ... (similar structure)
```

### Root.tsx - Main Routing Component

**File Location**: `src/private/components/threats/Root.tsx`

This is the central routing component that handles navigation between different threat entity types.

#### Key Features:

**1. Lazy Loading**: All components are loaded on-demand for better performance
```javascript
const ThreatActorsGroup = lazy(() => import('./ThreatActorsGroup'));
const IntrusionSets = lazy(() => import('./IntrusionSets'));
const Campaigns = lazy(() => import('./Campaigns'));
```

**2. Smart Redirects**: Automatically redirects to the first available entity type
```javascript
let redirect: string | null = null;
if (!useIsHiddenEntity('Threat-Actor-Group')) {
  redirect = 'threat_actors_group';
} else if (!useIsHiddenEntity('Intrusion-Set')) {
  redirect = 'intrusion_sets';
} else if (!useIsHiddenEntity('Campaign')) {
  redirect = 'campaigns';
}
```

**3. Route Configuration**: Defines all threat-related routes
```javascript
<Routes>
  <Route path="/threat_actors_group" element={boundaryWrapper(ThreatActorsGroup)} />
  <Route path="/threat_actors_group/:threatActorGroupId/*" element={boundaryWrapper(RootThreatActorGroup)} />
  <Route path="/intrusion_sets" element={boundaryWrapper(IntrusionSets)} />
  <Route path="/intrusion_sets/:intrusionSetId/*" element={boundaryWrapper(RootIntrusionSet)} />
  <Route path="/campaigns" element={boundaryWrapper(Campaigns)} />
  <Route path="/campaigns/:campaignId/*" element={boundaryWrapper(RootCampaign)} />
</Routes>
```

### List Pages (Campaigns.tsx, IntrusionSets.tsx)

These components handle the listing and overview of threat entities.

#### Key Features:

**1. Dual View Support**: Both card and table views
```javascript
const renderCards = () => {
  // Card view implementation
};

const renderList = () => {
  // Table view implementation
};
```

**2. Table Customization**: Custom column configurations
```javascript
const dataColumns = {
  name: { percentWidth: 15 },
  creator: { percentWidth: 13 },
  created: { percentWidth: 10 },
  modified: {},
  createdBy: {},
  objectLabel: {},
  x_opencti_workflow_id: {
    label: 'Processing status',
    percentWidth: 10,
  },
  objectMarking: { percentWidth: 10 },
};
```

**3. Header Button Customization**: Custom buttons in the table header
```javascript
additionalHeaderButtons={[
  (<ToggleButton key="cards" value="cards" aria-label="cards">
    <Tooltip title={t_i18n('Cards view')}>
      <ViewModuleOutlined fontSize="small" color="primary" />
    </Tooltip>
  </ToggleButton>),
  (<ToggleButton key="lines" value="lines" aria-label="lines">
    <Tooltip title={t_i18n('Lines view')}>
      <ViewListOutlined color="secondary" fontSize="small" />
    </Tooltip>
  </ToggleButton>),
]}
```

### Individual Entity Folders

Each threat entity type has its own folder with specialized components.

#### campaigns/ Folder Structure

**1. Root.tsx** - Entity detail routing
- Handles individual campaign detail pages
- Manages tabs and navigation within a campaign
- Implements GraphQL subscriptions for real-time updates

**2. Campaign.tsx** - Overview component
- Displays campaign overview with customizable layout
- Uses `useOverviewLayoutCustomization` for dynamic widget arrangement
- Renders different widgets based on configuration

**3. CampaignCard.tsx** - Card component
- Displays campaign information in card format
- Used in the cards view of the campaigns list

**4. CampaignCreation.tsx** - Creation form
- Handles new campaign creation
- Form validation and submission logic

**5. CampaignDetails.jsx** - Details view
- Comprehensive campaign information display
- Form fields and data presentation

**6. CampaignEdition.jsx** - Editing form
- Campaign modification interface
- Field updates and validation

#### intrusion_sets/ Folder Structure

Similar structure to campaigns but for intrusion sets:

**1. Root.tsx** - Intrusion set detail routing
**2. IntrusionSet.tsx** - Overview component
**3. IntrusionSetCard.tsx** - Card component
**4. IntrusionSetCreation.tsx** - Creation form
**5. IntrusionSetDetails.tsx** - Details view
**6. IntrusionSetEdition.jsx** - Editing form

### How to Customize Header Buttons

Header buttons can be customized in multiple locations:

#### 1. List Page Header Buttons

**Location**: `src/private/components/threats/Campaigns.tsx` (Lines 168-179)

```javascript
additionalHeaderButtons={[
  (<ToggleButton key="cards" value="cards" aria-label="cards">
    <Tooltip title={t_i18n('Cards view')}>
      <ViewModuleOutlined fontSize="small" color="primary" />
    </Tooltip>
  </ToggleButton>),
  (<ToggleButton key="lines" value="lines" aria-label="lines">
    <Tooltip title={t_i18n('Lines view')}>
      <ViewListOutlined color="secondary" fontSize="small" />
    </Tooltip>
  </ToggleButton>),
]}
```

**To Add Custom Buttons**:
```javascript
additionalHeaderButtons={[
  // Existing buttons...
  (<Button key="custom" variant="outlined" size="small">
    Custom Action
  </Button>),
]}
```

#### 2. Entity Detail Page Header

**Location**: `src/private/components/threats/campaigns/Root.tsx` (Lines 138-154)

```javascript
<StixDomainObjectHeader
  entityType="Campaign"
  stixDomainObject={campaign}
  EditComponent={(
    <Security needs={[KNOWLEDGE_KNUPDATE]}>
      <CampaignEdition campaignId={campaign.id} />
    </Security>
  )}
  DeleteComponent={({ isOpen, onClose }) => (
    <Security needs={[KNOWLEDGE_KNUPDATE_KNDELETE]}>
      <CampaignDeletion id={campaign.id} isOpen={isOpen} handleClose={onClose} />
    </Security>
  )}
  enableEnricher={true}
  enableQuickSubscription={true}
  redirectToContent={true}
/>
```

#### 3. Tab Navigation

**Location**: `src/private/components/threats/campaigns/Root.tsx` (Lines 165-204)

```javascript
<Tabs value={getCurrentTab(location.pathname, campaign.id, '/dashboard/threats/campaigns')}>
  <Tab
    component={Link}
    to={`/dashboard/threats/campaigns/${campaign.id}`}
    value={`/dashboard/threats/campaigns/${campaign.id}`}
    label={t_i18n('Overview')}
  />
  <Tab
    component={Link}
    to={`/dashboard/threats/campaigns/${campaign.id}/knowledge/overview`}
    value={`/dashboard/threats/campaigns/${campaign.id}/knowledge`}
    label={t_i18n('Knowledge')}
  />
  <Tab
    component={Link}
    to={`/dashboard/threats/campaigns/${campaign.id}/analyses`}
    value={`/dashboard/threats/campaigns/${campaign.id}/analyses`}
    label={t_i18n('Analyses')}
  />
  <Tab
    component={Link}
    to={`/dashboard/threats/campaigns/${campaign.id}/history`}
    value={`/dashboard/threats/campaigns/${campaign.id}/history`}
    label={t_i18n('History')}
  />
</Tabs>
```

**To Add Custom Tabs**:
```javascript
<Tab
  component={Link}
  to={`/dashboard/threats/campaigns/${campaign.id}/custom`}
  value={`/dashboard/threats/campaigns/${campaign.id}/custom`}
  label={t_i18n('Custom Tab')}
/>
```

### How to Edit Internal Pages

#### 1. Modify List Pages

**File**: `src/private/components/threats/Campaigns.tsx`

**Customize Columns**:
```javascript
const dataColumns = {
  name: { percentWidth: 20 },        // Increase name column width
  creator: { percentWidth: 15 },     // Adjust creator column
  // Add new column
  custom_field: {
    label: 'Custom Field',
    percentWidth: 10,
    isSortable: true,
  },
};
```

**Customize View Toggle**:
```javascript
// Change default view
const initialValues = {
  filters: emptyFilterGroup,
  searchTerm: '',
  sortBy: 'name',
  orderAsc: true,
  openExports: false,
  view: 'lines',  // Change from 'cards' to 'lines'
};
```

#### 2. Modify Entity Detail Pages

**File**: `src/private/components/threats/campaigns/Campaign.tsx`

**Customize Overview Layout**:
```javascript
const CampaignComponent = ({ campaignData }) => {
  const campaign = useFragment(campaignFragment, campaignData);
  const overviewLayoutCustomization = useOverviewLayoutCustomization(campaign.entity_type);

  return (
    <Grid container={true} spacing={3} style={{ marginBottom: 20 }}>
      {overviewLayoutCustomization.map(({ key, width }) => {
        switch (key) {
          case 'details':
            return (
              <Grid key={key} item xs={width}>
                <CampaignDetails campaign={campaign} />
              </Grid>
            );
          // Add custom widget
          case 'customWidget':
            return (
              <Grid key={key} item xs={width}>
                <CustomWidget campaign={campaign} />
              </Grid>
            );
          default:
            return null;
        }
      })}
    </Grid>
  );
};
```

#### 3. Add New Entity Types

**Step 1**: Create new folder structure
```
threats/
└── new_entity_type/
    ├── Root.tsx
    ├── NewEntityType.tsx
    ├── NewEntityTypeCard.tsx
    ├── NewEntityTypeCreation.tsx
    ├── NewEntityTypeDetails.tsx
    ├── NewEntityTypeEdition.jsx
    └── __generated__/
```

**Step 2**: Add to main Root.tsx
```javascript
const NewEntityType = lazy(() => import('./NewEntityType'));
const RootNewEntityType = lazy(() => import('./new_entity_type/Root'));

// Add route
<Route path="/new_entity_type" element={boundaryWrapper(NewEntityType)} />
<Route path="/new_entity_type/:newEntityTypeId/*" element={boundaryWrapper(RootNewEntityType)} />
```

**Step 3**: Update LeftBar navigation
```javascript
// In src/private/components/nav/LeftBar.jsx
generateSubMenu('threats', [
  { type: 'New-Entity-Type', link: '/dashboard/threats/new_entity_type', label: 'New Entity Type', icon: <NewIcon fontSize="small" /> },
])
```

### Key Benefits of This Structure

1. **Modularity**: Each entity type is self-contained
2. **Reusability**: Common patterns across all entity types
3. **Maintainability**: Clear separation of concerns
4. **Scalability**: Easy to add new entity types
5. **Customization**: Flexible header and layout customization
6. **Performance**: Lazy loading and code splitting
