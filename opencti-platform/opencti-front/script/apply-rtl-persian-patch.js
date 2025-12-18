const fs = require('fs');
const path = require('path');
const { exec } = require('child_process');
const { promisify } = require('util');

const execAsync = promisify(exec);

// Main async function
async function applyPatch() {
  console.log('🚀 Starting RTL and Persian patch application...\n');

// Helper function to read file
function readFile(filePath) {
  try {
    return fs.readFileSync(filePath, 'utf8');
  } catch (error) {
    console.error(`❌ Error reading file ${filePath}:`, error.message);
    return null;
  }
}

// Helper function to write file
function writeFile(filePath, content) {
  try {
    fs.writeFileSync(filePath, content, 'utf8');
    console.log(`✅ Updated: ${filePath}`);
    return true;
  } catch (error) {
    console.error(`❌ Error writing file ${filePath}:`, error.message);
    return false;
  }
}

// Helper function to copy file
function copyFile(source, destination) {
  try {
    const content = fs.readFileSync(source, 'utf8');
    fs.writeFileSync(destination, content, 'utf8');
    console.log(`✅ Created: ${destination}`);
    return true;
  } catch (error) {
    console.error(`❌ Error copying file from ${source} to ${destination}:`, error.message);
    return false;
  }
}

// Helper function to try Z.AI translation as fallback
async function tryZAITranslation(enPath, faPath) {
  const zaiApiKey = process.env.ZAI_API_KEY;
  if (!zaiApiKey) {
    console.log('   ⚠️  ZAI_API_KEY not set, skipping Z.AI fallback');
    return false;
  }
  
  try {
    const { translateFile } = require('./translate-with-zai.js');
    const baselineDir = path.join(__dirname, './local');
    // Create baseline directory if it doesn't exist
    if (!fs.existsSync(baselineDir)) {
      fs.mkdirSync(baselineDir, { recursive: true });
    }
    return await translateFile(enPath, faPath, baselineDir);
  } catch (error) {
    console.error('   ⚠️  Z.AI translation failed:', error.message);
    return false;
  }
}

// Helper function to recursively find files
function findFiles(dir, extensions, fileList = []) {
  const files = fs.readdirSync(dir);
  
  files.forEach(file => {
    const filePath = path.join(dir, file);
    const stat = fs.statSync(filePath);
    
    if (stat.isDirectory()) {
      // Skip node_modules, .git, and other common directories
      if (!['node_modules', '.git', 'dist', 'build', '__generated__', '.next'].includes(file)) {
        findFiles(filePath, extensions, fileList);
      }
    } else if (extensions.some(ext => file.endsWith(ext))) {
      fileList.push(filePath);
    }
  });
  
  return fileList;
}

// Convert CSS properties to RTL-safe
async function convertCSSToRTL() {
  const srcDir = path.join(__dirname, '../src');
  
  if (!fs.existsSync(srcDir)) {
    console.log('   ⚠️  src directory not found, skipping CSS conversion...');
    return;
  }

  // Find all TSX, JSX, and CSS files
  const tsxFiles = findFiles(srcDir, ['.tsx', '.jsx']);
  const cssFiles = findFiles(srcDir, ['.css']);
  const allFiles = [...tsxFiles, ...cssFiles];
  
  console.log(`   📁 Found ${allFiles.length} files to check...`);
  
  let convertedCount = 0;
  let skippedCount = 0;
  
  for (const filePath of allFiles) {
    try {
      let content = fs.readFileSync(filePath, 'utf8');
      const originalContent = content;
      let fileChanged = false;
      
      // Check if file has properties that need conversion
      const needsConversion = content.includes('marginLeft') || 
                             content.includes('marginRight') ||
                             content.includes('paddingLeft') || 
                             content.includes('paddingRight') ||
                             content.includes('margin-left') || 
                             content.includes('margin-right') ||
                             content.includes('padding-left') || 
                             content.includes('padding-right') ||
                             content.includes('borderTopLeftRadius') ||
                             content.includes('borderTopRightRadius') ||
                             content.includes('border-bottom-left-radius') ||
                             content.includes('border-bottom-right-radius');
      
      // Only process files that need conversion
      if (needsConversion) {
        
        // Convert JavaScript/TypeScript style objects (camelCase)
        // marginLeft -> marginInlineStart, marginRight -> marginInlineEnd
        // paddingLeft -> paddingInlineStart, paddingRight -> paddingInlineEnd
        // Note: We're being careful with left/right as they might be used in other contexts
        
        // Pattern for object properties: marginLeft: value or 'marginLeft': value
        const jsStylePatterns = [
          // Margin and padding conversions (safe)
          { from: /(['"]?)marginLeft\1\s*:/g, to: '$1marginInlineStart$1:' },
          { from: /(['"]?)marginRight\1\s*:/g, to: '$1marginInlineEnd$1:' },
          { from: /(['"]?)paddingLeft\1\s*:/g, to: '$1paddingInlineStart$1:' },
          { from: /(['"]?)paddingRight\1\s*:/g, to: '$1paddingInlineEnd$1:' },
          // Border radius conversions
          { from: /(['"]?)borderTopLeftRadius\1\s*:/g, to: '$1borderStartStartRadius$1:' },
          { from: /(['"]?)borderTopRightRadius\1\s*:/g, to: '$1borderStartEndRadius$1:' },
          { from: /(['"]?)borderBottomLeftRadius\1\s*:/g, to: '$1borderEndStartRadius$1:' },
          { from: /(['"]?)borderBottomRightRadius\1\s*:/g, to: '$1borderEndEndRadius$1:' },
        ];
        
        // Convert CSS files (kebab-case)
        // margin-left -> margin-inline-start, margin-right -> margin-inline-end
        // padding-left -> padding-inline-start, padding-right -> padding-inline-end
        const cssStylePatterns = [
          { from: /\bmargin-left\s*:/g, to: 'margin-inline-start:' },
          { from: /\bmargin-right\s*:/g, to: 'margin-inline-end:' },
          { from: /\bpadding-left\s*:/g, to: 'padding-inline-start:' },
          { from: /\bpadding-right\s*:/g, to: 'padding-inline-end:' },
          { from: /\bborder-top-left-radius\s*:/g, to: 'border-start-start-radius:' },
          { from: /\bborder-top-right-radius\s*:/g, to: 'border-start-end-radius:' },
          { from: /\bborder-bottom-left-radius\s*:/g, to: 'border-end-start-radius:' },
          { from: /\bborder-bottom-right-radius\s*:/g, to: 'border-end-end-radius:' },
        ];
        
        const isCSS = filePath.endsWith('.css');
        const patterns = isCSS ? cssStylePatterns : jsStylePatterns;
        
        for (const pattern of patterns) {
          if (pattern.from.test(content)) {
            content = content.replace(pattern.from, pattern.to);
            fileChanged = true;
          }
        }
        
        // Also handle float: left/right -> float: inline-start/inline-end (only in style objects)
        if (!isCSS && (content.includes('float:') || content.includes('float\''))) {
          content = content.replace(/(['"]?)float\1\s*:\s*['"]left['"]/g, '$1float$1: \'inline-start\'');
          content = content.replace(/(['"]?)float\1\s*:\s*['"]right['"]/g, '$1float$1: \'inline-end\'');
          if (content !== originalContent) fileChanged = true;
        } else if (isCSS && content.includes('float:')) {
          content = content.replace(/\bfloat\s*:\s*left\b/g, 'float: inline-start');
          content = content.replace(/\bfloat\s*:\s*right\b/g, 'float: inline-end');
          if (content !== originalContent) fileChanged = true;
        }
        
        // Handle textAlign: left/right -> textAlign: start/end (only in style objects)
        if (!isCSS && (content.includes('textAlign:') || content.includes('text-align:'))) {
          content = content.replace(/textAlign\s*:\s*['"]left['"]/g, 'textAlign: \'start\'');
          content = content.replace(/textAlign\s*:\s*['"]right['"]/g, 'textAlign: \'end\'');
          if (content !== originalContent) fileChanged = true;
        }
        
        // Handle text-align in CSS
        if (isCSS && content.includes('text-align:')) {
          content = content.replace(/\btext-align\s*:\s*left\b/g, 'text-align: start');
          content = content.replace(/\btext-align\s*:\s*right\b/g, 'text-align: end');
          if (content !== originalContent) fileChanged = true;
        }
        
        if (fileChanged && content !== originalContent) {
          fs.writeFileSync(filePath, content, 'utf8');
          convertedCount++;
          const relativePath = path.relative(path.join(__dirname, '..'), filePath);
          console.log(`   ✅ Converted: ${relativePath}`);
        } else {
          skippedCount++;
        }
      } else {
        skippedCount++;
      }
    } catch (error) {
      console.error(`   ⚠️  Error processing ${filePath}:`, error.message);
    }
  }
  
  if (convertedCount > 0) {
    console.log(`   ✨ Converted ${convertedCount} file(s) to RTL-safe properties`);
  }
  if (skippedCount > 0) {
    console.log(`   ℹ️  Skipped ${skippedCount} file(s) (already RTL-safe or no changes needed)`);
  }
}

  // 1. Update AppThemeProvider.tsx for RTL support
  console.log('📝 Step 1: Checking AppThemeProvider.tsx for RTL support...');
  const appThemeProviderPath = path.join(__dirname, '../src/components/AppThemeProvider.tsx');
  let appThemeProviderContent = readFile(appThemeProviderPath);

  if (appThemeProviderContent) {
    // Check if RTL is already applied
    const isRTLAlreadyApplied = appThemeProviderContent.includes('stylis-plugin-rtl') 
      && appThemeProviderContent.includes('CacheProvider')
      && appThemeProviderContent.includes('useDocumentDirectionModifier')
      && appThemeProviderContent.includes('cacheRTL');
    
    if (isRTLAlreadyApplied) {
      console.log('   ✅ RTL support already applied, skipping...');
    } else {
      console.log('   📝 Applying RTL support...');
      // Add useContext and useMemo to React imports
      if (!appThemeProviderContent.includes("import { useContext }") && !appThemeProviderContent.includes("import { useMemo }")) {
        appThemeProviderContent = appThemeProviderContent.replace(
          /import React, { FunctionComponent } from 'react';/,
          "import React, { FunctionComponent, useContext, useMemo } from 'react';"
        );
      } else if (!appThemeProviderContent.includes("useMemo")) {
        appThemeProviderContent = appThemeProviderContent.replace(
          /import React, { FunctionComponent, useContext } from 'react';/,
          "import React, { FunctionComponent, useContext, useMemo } from 'react';"
        );
      } else if (!appThemeProviderContent.includes("useContext")) {
        appThemeProviderContent = appThemeProviderContent.replace(
          /import React, { FunctionComponent, useMemo } from 'react';/,
          "import React, { FunctionComponent, useContext, useMemo } from 'react';"
        );
      }

      // Update useDocumentModifier import
      appThemeProviderContent = appThemeProviderContent.replace(
        /import { useDocumentFaviconModifier, useDocumentThemeModifier } from '\.\.\/utils\/hooks\/useDocumentModifier';/,
        "import { useDocumentFaviconModifier, useDocumentThemeModifier, useDocumentDirectionModifier } from '../utils/hooks/useDocumentModifier';"
      );

      // Add RTL-related imports after the useDocumentModifier import
      const rtlImports = `import rtlPlugin from 'stylis-plugin-rtl';
import createCache from '@emotion/cache';
import { CacheProvider } from '@emotion/react';
import { prefixer } from 'stylis';
import { UserContext, UserContextType } from '../utils/hooks/useAuth';

const cacheRTL = createCache({
  key: 'mui-style-rtl',
  prepend: true,
  stylisPlugins: [prefixer, rtlPlugin],
});
`;

      // Insert RTL imports after the AppThemeProvider_settings import
      appThemeProviderContent = appThemeProviderContent.replace(
        /(import { AppThemeProvider_settings\$data } from '\.\/__generated__\/AppThemeProvider_settings\.graphql';)/,
        `$1\n${rtlImports}`
      );

      // Update the component function
      const oldComponent = `const AppThemeProvider: FunctionComponent<AppThemeProviderProps> = ({
  children,
  settings,
  activeTheme,
}) => {
  useDocumentFaviconModifier(settings?.platform_favicon);

  const themeToUse = activeTheme || settings.platform_theme;

  const appTheme: AppThemeType = {
    name: themeToUse?.name ?? defaultTheme.name,
    theme_accent: themeToUse?.theme_accent ?? defaultTheme.theme_accent,
    theme_background: themeToUse?.theme_background ?? defaultTheme.theme_background,
    theme_logo: themeToUse?.theme_logo ?? defaultTheme.theme_logo,
    theme_logo_collapsed: themeToUse?.theme_logo_collapsed ?? defaultTheme.theme_logo_collapsed,
    theme_logo_login: themeToUse?.theme_logo_login ?? defaultTheme.theme_logo_login,
    theme_nav: themeToUse?.theme_nav ?? defaultTheme.theme_nav,
    theme_paper: themeToUse?.theme_paper ?? defaultTheme.theme_paper,
    theme_primary: themeToUse?.theme_primary ?? defaultTheme.theme_primary,
    theme_secondary: themeToUse?.theme_secondary ?? defaultTheme.theme_secondary,
    theme_text_color: themeToUse?.theme_text_color ?? defaultTheme.theme_text_color,
  };

  const themeComponent = themeBuilder(appTheme);
  const muiTheme = createTheme(themeComponent as ThemeOptions);
  useDocumentThemeModifier(appTheme.name);

  return <ThemeProvider theme={muiTheme}>{children}</ThemeProvider>;
};`;

      const newComponent = `const AppThemeProvider: FunctionComponent<AppThemeProviderProps> = ({
  children,
  settings,
  activeTheme,
}) => {
  const { me } = useContext<UserContextType>(UserContext);
  useDocumentFaviconModifier(settings?.platform_favicon);

  const themeToUse = activeTheme || settings.platform_theme;

  const appTheme: AppThemeType = {
    name: themeToUse?.name ?? defaultTheme.name,
    theme_accent: themeToUse?.theme_accent ?? defaultTheme.theme_accent,
    theme_background: themeToUse?.theme_background ?? defaultTheme.theme_background,
    theme_logo: themeToUse?.theme_logo ?? defaultTheme.theme_logo,
    theme_logo_collapsed: themeToUse?.theme_logo_collapsed ?? defaultTheme.theme_logo_collapsed,
    theme_logo_login: themeToUse?.theme_logo_login ?? defaultTheme.theme_logo_login,
    theme_nav: themeToUse?.theme_nav ?? defaultTheme.theme_nav,
    theme_paper: themeToUse?.theme_paper ?? defaultTheme.theme_paper,
    theme_primary: themeToUse?.theme_primary ?? defaultTheme.theme_primary,
    theme_secondary: themeToUse?.theme_secondary ?? defaultTheme.theme_secondary,
    theme_text_color: themeToUse?.theme_text_color ?? defaultTheme.theme_text_color,
  };

  const themeComponent = themeBuilder(appTheme);
  const muiTheme = createTheme(themeComponent as ThemeOptions);
  useDocumentThemeModifier(appTheme.name);

  // RTL support - get language from UserContext or settings
  // Note: We need to get settings from UserContext since AppThemeProvider_settings doesn't include platform_language
  const userContext = useContext(UserContext);
  const userLanguage = me?.language ?? null;
  const platformLanguage = userContext?.settings?.platform_language ?? null;
  
  // Determine current language: user language > platform language > default
  // Use useMemo to recalculate when UserContext updates
  const direction: 'rtl' | 'ltr' = useMemo(() => {
    let currentLang = 'en-us';
    if (userLanguage && userLanguage !== 'auto') {
      currentLang = userLanguage;
    } else if (platformLanguage && platformLanguage !== 'auto') {
      currentLang = platformLanguage;
    }
    return currentLang === 'fa-ir' ? 'rtl' : 'ltr';
  }, [userLanguage, platformLanguage]);
  
  useDocumentDirectionModifier(direction);

  if (direction === 'rtl') {
    return (
      <CacheProvider value={cacheRTL}>
        <ThemeProvider theme={muiTheme}>{children}</ThemeProvider>
      </CacheProvider>
    );
  }

  return <ThemeProvider theme={muiTheme}>{children}</ThemeProvider>;
};`;

      appThemeProviderContent = appThemeProviderContent.replace(oldComponent, newComponent);

      writeFile(appThemeProviderPath, appThemeProviderContent);
    }
  } else {
    console.log('   ⚠️  AppThemeProvider.tsx not found, skipping...');
  }

  // 2. Update AppIntlProvider.tsx for Persian support
  console.log('\n📝 Step 2: Checking AppIntlProvider.tsx for Persian support...');
  const appIntlProviderPath = path.join(__dirname, '../src/components/AppIntlProvider.tsx');
  let appIntlProviderContent = readFile(appIntlProviderPath);

  if (appIntlProviderContent) {
    // Check if Persian is already added
    const isPersianAlreadyAdded = appIntlProviderContent.includes("'fa-ir'")
      && appIntlProviderContent.includes('messages_fa_front')
      && appIntlProviderContent.includes('messages_fa_back')
      && appIntlProviderContent.includes('faIR')
      && appIntlProviderContent.includes("label: 'فارسی'");
    
    if (isPersianAlreadyAdded) {
      console.log('   ✅ Persian support already added, skipping...');
    } else {
      console.log('   📝 Adding Persian support...');
      // Add faIR import from date-fns
      appIntlProviderContent = appIntlProviderContent.replace(
        /import { de, enUS, es, fr, it, ja, ko, zhCN, ru } from 'date-fns\/locale';/,
        "import { de, enUS, es, fr, it, ja, ko, zhCN, ru, faIR } from 'date-fns/locale';"
      );

      // Add Persian message imports
      appIntlProviderContent = appIntlProviderContent.replace(
        /import messages_ru_front from '\.\.\/\.\.\/lang\/front\/ru\.json';/,
        `import messages_ru_front from '../../lang/front/ru.json';
import messages_fa_front from '../../lang/front/fa.json';`
      );

      appIntlProviderContent = appIntlProviderContent.replace(
        /import messages_ru_back from '\.\.\/\.\.\/lang\/back\/ru\.json';/,
        `import messages_ru_back from '../../lang/back/ru.json';
import messages_fa_back from '../../lang/back/fa.json';`
      );

      // Add 'fa-ir' to PlatformLang type
      appIntlProviderContent = appIntlProviderContent.replace(
        /type PlatformLang\s*=\s*\|\s*'de-de'\s*\|\s*'en-us'\s*\|\s*'es-es'\s*\|\s*'fr-fr'\s*\|\s*'it-it'\s*\|\s*'ja-jp'\s*\|\s*'ko-kr'\s*\|\s*'zh-cn'\s*\|\s*'ru-ru';/,
        "type PlatformLang\n  = | 'de-de'\n    | 'en-us'\n    | 'fa-ir'\n    | 'es-es'\n    | 'fr-fr'\n    | 'it-it'\n    | 'ja-jp'\n    | 'ko-kr'\n    | 'zh-cn'\n    | 'ru-ru';"
      );

      // Add fa-ir to localeMap
      appIntlProviderContent = appIntlProviderContent.replace(
        /const localeMap: Record<PlatformLang, Locale> = \{[\s\S]*?'ru-ru': ru,\s*\};/,
        `const localeMap: Record<PlatformLang, Locale> = {
  'de-de': de,
  'en-us': enUS,
  'fa-ir': faIR,
  'es-es': es,
  'fr-fr': fr,
  'it-it': it,
  'ja-jp': ja,
  'ko-kr': ko,
  'zh-cn': zhCN,
  'ru-ru': ru,
};`
      );

      // Add fa-ir to i18n messages
      appIntlProviderContent = appIntlProviderContent.replace(
        /'ru-ru': \{ \.\.\.messages_ru_back, \.\.\.messages_ru_front \},\s*\},/,
        `'ru-ru': { ...messages_ru_back, ...messages_ru_front },
    'fa-ir': { ...messages_fa_back, ...messages_fa_front },
  },`
      );

      // Add Persian to availableLanguage array
      appIntlProviderContent = appIntlProviderContent.replace(
        /{ value: 'en-us', label: 'English', name: 'English' },/,
        `{ value: 'en-us', label: 'English', name: 'English' },
  { value: 'fa-ir', label: 'فارسی', name: 'Persian' },`
      );

      writeFile(appIntlProviderPath, appIntlProviderContent);
    }
  } else {
    console.log('   ⚠️  AppIntlProvider.tsx not found, skipping...');
  }

  // 3. Update useDocumentModifier.ts to add useDocumentDirectionModifier
  console.log('\n📝 Step 3: Checking useDocumentModifier.ts for useDocumentDirectionModifier...');
  const useDocumentModifierPath = path.join(__dirname, '../src/utils/hooks/useDocumentModifier.ts');
  let useDocumentModifierContent = readFile(useDocumentModifierPath);

  if (useDocumentModifierContent) {
    if (useDocumentModifierContent.includes('useDocumentDirectionModifier')) {
      console.log('   ✅ useDocumentDirectionModifier already exists, skipping...');
    } else {
      console.log('   📝 Adding useDocumentDirectionModifier...');
      const directionModifier = `
export const useDocumentDirectionModifier = (direction: 'rtl' | 'ltr') => {
  useEffect(() => {
    const prevDir = document.documentElement.dir;
    if (prevDir !== direction) {
      document.documentElement.dir = direction;
    }
    return () => {
      document.documentElement.dir = prevDir;
    };
  }, [direction]);
};
`;

      useDocumentModifierContent += directionModifier;
      writeFile(useDocumentModifierPath, useDocumentModifierContent);
    }
  } else {
    console.log('   ⚠️  useDocumentModifier.ts not found, skipping...');
  }

  // 4. Create Persian translation files
  console.log('\n📝 Step 4: Checking Persian translation files...');
  const langFrontEnPath = path.join(__dirname, '../lang/front/en.json');
  const langFrontFaPath = path.join(__dirname, '../lang/front/fa.json');
  const langBackEnPath = path.join(__dirname, '../lang/back/en.json');
  const langBackFaPath = path.join(__dirname, '../lang/back/fa.json');

  let shouldTranslate = false;
  let needsTranslation = false;

  // Check front translation file
  if (!fs.existsSync(langFrontEnPath)) {
    console.log('   ⚠️  English front translation file not found, skipping...');
  } else if (!fs.existsSync(langFrontFaPath)) {
    console.log('   📝 Creating lang/front/fa.json...');
    copyFile(langFrontEnPath, langFrontFaPath);
    shouldTranslate = true;
    needsTranslation = true;
  } else {
    // Check if file is empty or just a copy of English (needs translation)
    try {
      const faContent = JSON.parse(fs.readFileSync(langFrontFaPath, 'utf8'));
      const enContent = JSON.parse(fs.readFileSync(langFrontEnPath, 'utf8'));
      // If files are identical, it needs translation
      if (JSON.stringify(faContent) === JSON.stringify(enContent)) {
        console.log('   ⚠️  lang/front/fa.json exists but appears to be untranslated (identical to English)');
        needsTranslation = true;
      } else {
        console.log('   ✅ lang/front/fa.json already exists and appears to be translated');
      }
    } catch (error) {
      console.log('   ⚠️  lang/front/fa.json exists but may be corrupted, will attempt translation');
      needsTranslation = true;
    }
  }

  // Check back translation file
  if (!fs.existsSync(langBackEnPath)) {
    console.log('   ⚠️  English back translation file not found, skipping...');
  } else if (!fs.existsSync(langBackFaPath)) {
    console.log('   📝 Creating lang/back/fa.json...');
    copyFile(langBackEnPath, langBackFaPath);
    shouldTranslate = true;
    needsTranslation = true;
  } else {
    // Check if file is empty or just a copy of English (needs translation)
    try {
      const faContent = JSON.parse(fs.readFileSync(langBackFaPath, 'utf8'));
      const enContent = JSON.parse(fs.readFileSync(langBackEnPath, 'utf8'));
      // If files are identical, it needs translation
      if (JSON.stringify(faContent) === JSON.stringify(enContent)) {
        console.log('   ⚠️  lang/back/fa.json exists but appears to be untranslated (identical to English)');
        needsTranslation = true;
      } else {
        console.log('   ✅ lang/back/fa.json already exists and appears to be translated');
      }
    } catch (error) {
      console.log('   ⚠️  lang/back/fa.json exists but may be corrupted, will attempt translation');
      needsTranslation = true;
    }
  }

  // 4.1. Auto-translate Persian files if SUBSCRIPTION_KEY or ZAI_API_KEY is available
  if (shouldTranslate || needsTranslation) {
    console.log('\n📝 Step 4.1: Checking for auto-translation...');
    const subscriptionKey = process.env.SUBSCRIPTION_KEY;
    const zaiApiKey = process.env.ZAI_API_KEY;
    
    if (subscriptionKey) {
      console.log('✅ SUBSCRIPTION_KEY found, using DeepL for translation...');
      console.log('   This may take a few minutes...\n');
      
      try {
        // Translate front file
        if (fs.existsSync(langFrontFaPath)) {
          console.log('   Translating lang/front/fa.json...');
          const frontCommand = `i18n-auto-translation -a deepl-free -p ${langFrontEnPath} -t fa -k ${subscriptionKey}`;
          try {
            const { stdout } = await execAsync(frontCommand);
            console.log('   ✅ Front translation completed');
          } catch (error) {
            console.error('   ⚠️  Error translating front file:', error.message);
            console.log('   ℹ️  Trying Z.AI as fallback...');
            // Try Z.AI as fallback
            await tryZAITranslation(langFrontEnPath, langFrontFaPath);
          }
        }
        
        // Translate back file
        if (fs.existsSync(langBackFaPath)) {
          console.log('   Translating lang/back/fa.json...');
          const backCommand = `i18n-auto-translation -a deepl-free -p ${langBackEnPath} -t fa -k ${subscriptionKey}`;
          try {
            const { stdout } = await execAsync(backCommand);
            console.log('   ✅ Back translation completed');
          } catch (error) {
            console.error('   ⚠️  Error translating back file:', error.message);
            console.log('   ℹ️  Trying Z.AI as fallback...');
            // Try Z.AI as fallback
            await tryZAITranslation(langBackEnPath, langBackFaPath);
          }
        }
        
        console.log('\n   ✨ Auto-translation completed!');
      } catch (error) {
        console.error('   ❌ Error during auto-translation:', error.message);
        if (zaiApiKey) {
          console.log('   ℹ️  Trying Z.AI as fallback...');
          await tryZAITranslation(langFrontEnPath, langFrontFaPath);
          await tryZAITranslation(langBackEnPath, langBackFaPath);
        } else {
      console.log('   ℹ️  You can translate files manually or run:');
      console.log('      Linux/Mac/Git Bash:');
      console.log('        export SUBSCRIPTION_KEY=your_key && node script/auto-translate.js');
      console.log('        export ZAI_API_KEY=your_key && node script/translate-with-zai.js');
      console.log('      Windows PowerShell:');
      console.log('        $env:SUBSCRIPTION_KEY="your_key"; node script/auto-translate.js');
      console.log('        $env:ZAI_API_KEY="your_key"; node script/translate-with-zai.js');
      console.log('      Windows CMD:');
      console.log('        set SUBSCRIPTION_KEY=your_key && node script/auto-translate.js');
      console.log('        set ZAI_API_KEY=your_key && node script/translate-with-zai.js');
        }
      }
    } else if (zaiApiKey) {
      console.log('✅ ZAI_API_KEY found, using Z.AI for translation...');
      console.log('   This may take a few minutes...\n');
      
      try {
        const { translateFile } = require('./translate-with-zai.js');
        const baselineDir = path.join(__dirname, './local');
        // Create baseline directory if it doesn't exist
        if (!fs.existsSync(baselineDir)) {
          fs.mkdirSync(baselineDir, { recursive: true });
        }
        await translateFile(langFrontEnPath, langFrontFaPath, baselineDir);
        await translateFile(langBackEnPath, langBackFaPath, baselineDir);
        console.log('\n   ✨ Auto-translation completed!');
      } catch (error) {
        console.error('   ❌ Error during Z.AI translation:', error.message);
      console.log('   ℹ️  You can translate files manually or run:');
      console.log('      Linux/Mac/Git Bash:');
      console.log('        export ZAI_API_KEY=your_key && node script/translate-with-zai.js');
      console.log('      Windows PowerShell:');
      console.log('        $env:ZAI_API_KEY="your_key"; node script/translate-with-zai.js');
      console.log('      Windows CMD:');
      console.log('        set ZAI_API_KEY=your_key && node script/translate-with-zai.js');
      }
    } else {
      console.log('⚠️  No translation API key found.');
      console.log('   To enable auto-translation, set one of these:');
      console.log('   Option 1 - DeepL (recommended):');
      console.log('     1. Get a DeepL API key (free tier available at https://www.deepl.com/pro-api)');
      console.log('     2. Set environment variable:');
      console.log('        Linux/Mac/Git Bash: export SUBSCRIPTION_KEY=your_key');
      console.log('        Windows PowerShell: $env:SUBSCRIPTION_KEY="your_key"');
      console.log('        Windows CMD: set SUBSCRIPTION_KEY=your_key');
      console.log('     3. Run: node script/apply-rtl-persian-patch.js');
      console.log('   Option 2 - Z.AI:');
      console.log('     1. Get a Z.AI API key');
      console.log('     2. Set environment variable:');
      console.log('        Linux/Mac/Git Bash: export ZAI_API_KEY=your_key');
      console.log('        Windows PowerShell: $env:ZAI_API_KEY="your_key"');
      console.log('        Windows CMD: set ZAI_API_KEY=your_key');
      console.log('     3. Run: node script/apply-rtl-persian-patch.js');
      console.log('   Or translate manually: lang/front/fa.json and lang/back/fa.json');
    }
  }

  // 5. Convert CSS properties to RTL-safe (marginLeft/Right, paddingLeft/Right, left/right)
  console.log('\n📝 Step 5: Converting CSS properties to RTL-safe...');
  await convertCSSToRTL();

  // 6. Update package.json to add stylis-plugin-rtl dependency
  console.log('\n📝 Step 6: Checking package.json for stylis-plugin-rtl...');
  const packageJsonPath = path.join(__dirname, '../package.json');
  let packageJsonContent = readFile(packageJsonPath);

  if (packageJsonContent) {
    const packageJson = JSON.parse(packageJsonContent);
    
    if (packageJson.dependencies && packageJson.dependencies['stylis-plugin-rtl']) {
      console.log('   ✅ stylis-plugin-rtl already exists in dependencies, skipping...');
    } else {
      console.log('   📝 Adding stylis-plugin-rtl to dependencies...');
      if (!packageJson.dependencies) {
        packageJson.dependencies = {};
      }
      packageJson.dependencies['stylis-plugin-rtl'] = '^2.1.1';
      packageJsonContent = JSON.stringify(packageJson, null, 2);
      writeFile(packageJsonPath, packageJsonContent);
      console.log('   ⚠️  Please run "yarn install" to install the new dependency: stylis-plugin-rtl');
    }
  } else {
    console.log('   ⚠️  package.json not found, skipping...');
  }

  console.log('\n✨ Patch application completed!');
  console.log('\n📋 Next steps:');
  console.log('   1. Run: yarn install');
  if (!process.env.SUBSCRIPTION_KEY && !process.env.ZAI_API_KEY) {
    console.log('   2. Translate the Persian files:');
    console.log('      Option A - DeepL (recommended):');
    console.log('        - Get DeepL API key (free tier available at https://www.deepl.com/pro-api)');
    console.log('        - Set: Linux/Mac: export SUBSCRIPTION_KEY=your_key');
    console.log('               Windows PowerShell: $env:SUBSCRIPTION_KEY="your_key"');
    console.log('               Windows CMD: set SUBSCRIPTION_KEY=your_key');
    console.log('        - Run: node script/apply-rtl-persian-patch.js');
    console.log('      Option B - Z.AI:');
    console.log('        - Get Z.AI API key');
    console.log('        - Set: Linux/Mac: export ZAI_API_KEY=your_key');
    console.log('               Windows PowerShell: $env:ZAI_API_KEY="your_key"');
    console.log('               Windows CMD: set ZAI_API_KEY=your_key');
    console.log('        - Run: node script/apply-rtl-persian-patch.js');
    console.log('      Option C - Manual translation:');
    console.log('        - Edit: lang/front/fa.json and lang/back/fa.json');
    console.log('      Option D - Use existing scripts:');
    console.log('        - DeepL:');
    console.log('          Linux/Mac: export SUBSCRIPTION_KEY=your_key && node script/auto-translate.js');
    console.log('          Windows PowerShell: $env:SUBSCRIPTION_KEY="your_key"; node script/auto-translate.js');
    console.log('          Windows CMD: set SUBSCRIPTION_KEY=your_key && node script/auto-translate.js');
    console.log('        - Z.AI:');
    console.log('          Linux/Mac: export ZAI_API_KEY=your_key && node script/translate-with-zai.js');
    console.log('          Windows PowerShell: $env:ZAI_API_KEY="your_key"; node script/translate-with-zai.js');
    console.log('          Windows CMD: set ZAI_API_KEY=your_key && node script/translate-with-zai.js');
  } else {
    console.log('   2. ✅ Translation completed automatically (if successful)');
    console.log('      Review and refine translations in lang/front/fa.json and lang/back/fa.json if needed');
  }
  console.log('   3. Test the application with Persian language selected');
  console.log('\n🎉 Done!');
}

// Run the patch
applyPatch().catch((error) => {
  console.error('\n❌ Fatal error:', error.message);
  process.exit(1);
});

