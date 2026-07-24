import { readFileSync, writeFileSync } from 'node:fs';

// key -> per-language translation (en value is the key itself unless mapped)
const translations = {
  'Academy': {
    en: 'Academy', de: 'Academy', es: 'Academy', fr: 'Academy', it: 'Academy',
    ja: '\u30a2\u30ab\u30c7\u30df\u30fc', ko: '\uc544\uce74\ub370\ubbf8', ru: '\u0410\u043a\u0430\u0434\u0435\u043c\u0438\u044f', zh: '\u5b66\u9662',
  },
  'Community edition': {
    en: 'Community edition', de: 'Community-Edition', es: 'Edici\u00f3n comunitaria', fr: '\u00c9dition communautaire', it: 'Edizione community',
    ja: '\u30b3\u30df\u30e5\u30cb\u30c6\u30a3\u30a8\u30c7\u30a3\u30b7\u30e7\u30f3', ko: '\ucee4\ubba4\ub2c8\ud2f0 \uc5d0\ub514\uc158', ru: '\u0412\u0435\u0440\u0441\u0438\u044f Community', zh: '\u793e\u533a\u7248',
  },
  'Connected by': {
    en: 'Connected by', de: 'Verbunden von', es: 'Conectado por', fr: 'Connect\u00e9 par', it: 'Connesso da',
    ja: '\u63a5\u7d9a\u8005', ko: '\uc5f0\uacb0\ud55c \uc0ac\uc6a9\uc790', ru: '\u041f\u043e\u0434\u043a\u043b\u044e\u0447\u0438\u043b', zh: '\u8fde\u63a5\u8005',
  },
  'Connection date': {
    en: 'Connection date', de: 'Verbindungsdatum', es: 'Fecha de conexi\u00f3n', fr: 'Date de connexion', it: 'Data di connessione',
    ja: '\u63a5\u7d9a\u65e5', ko: '\uc5f0\uacb0 \ub0a0\uc9dc', ru: '\u0414\u0430\u0442\u0430 \u043f\u043e\u0434\u043a\u043b\u044e\u0447\u0435\u043d\u0438\u044f', zh: '\u8fde\u63a5\u65e5\u671f',
  },
  'Connection status': {
    en: 'Connection status', de: 'Verbindungsstatus', es: 'Estado de la conexi\u00f3n', fr: 'Statut de la connexion', it: 'Stato della connessione',
    ja: '\u63a5\u7d9a\u30b9\u30c6\u30fc\u30bf\u30b9', ko: '\uc5f0\uacb0 \uc0c1\ud0dc', ru: '\u0421\u0442\u0430\u0442\u0443\u0441 \u043f\u043e\u0434\u043a\u043b\u044e\u0447\u0435\u043d\u0438\u044f', zh: '\u8fde\u63a5\u72b6\u6001',
  },
  'Explore XTM Hub': {
    en: 'Explore XTM Hub', de: 'XTM Hub entdecken', es: 'Explorar XTM Hub', fr: 'Explorer XTM Hub', it: 'Esplora XTM Hub',
    ja: 'XTM Hub\u3092\u63a2\u7d22', ko: 'XTM Hub \uc0b4\ud3b4\ubcf4\uae30', ru: '\u0418\u0437\u0443\u0447\u0438\u0442\u044c XTM Hub', zh: '\u63a2\u7d22 XTM Hub',
  },
  'Extend and scale your OpenCTI experience': {
    en: 'Extend and scale your OpenCTI experience',
    de: 'Erweitern und skalieren Sie Ihre OpenCTI-Erfahrung',
    es: 'Ampl\u00ede y escale su experiencia OpenCTI',
    fr: '\u00c9tendez et d\u00e9veloppez votre exp\u00e9rience OpenCTI',
    it: 'Estendi e potenzia la tua esperienza OpenCTI',
    ja: 'OpenCTI\u30a8\u30af\u30b9\u30da\u30ea\u30a8\u30f3\u30b9\u3092\u62e1\u5f35\u30fb\u5f37\u5316',
    ko: 'OpenCTI \uacbd\ud5d8\uc744 \ud655\uc7a5\ud558\uace0 \ubc1c\uc804\uc2dc\ud0a4\uc138\uc694',
    ru: '\u0420\u0430\u0441\u0448\u0438\u0440\u044c\u0442\u0435 \u0438 \u043c\u0430\u0441\u0448\u0442\u0430\u0431\u0438\u0440\u0443\u0439\u0442\u0435 \u0432\u043e\u0437\u043c\u043e\u0436\u043d\u043e\u0441\u0442\u0438 OpenCTI',
    zh: '\u6269\u5c55\u5e76\u63d0\u5347\u60a8\u7684 OpenCTI \u4f53\u9a8c',
  },
  'Go to the Hub': {
    en: 'Go to the Hub', de: 'Zum Hub', es: 'Ir al Hub', fr: 'Acc\u00e9der au Hub', it: "Vai all'Hub",
    ja: 'Hub\u3078\u79fb\u52d5', ko: 'Hub\ub85c \uc774\ub3d9', ru: '\u041f\u0435\u0440\u0435\u0439\u0442\u0438 \u0432 Hub', zh: '\u524d\u5f80 Hub',
  },
  'Not connected': {
    en: 'Not connected', de: 'Nicht verbunden', es: 'No conectado', fr: 'Non connect\u00e9', it: 'Non connesso',
    ja: '\u672a\u63a5\u7d9a', ko: '\uc5f0\uacb0\ub418\uc9c0 \uc54a\uc74c', ru: '\u041d\u0435 \u043f\u043e\u0434\u043a\u043b\u044e\u0447\u0435\u043d\u043e', zh: '\u672a\u8fde\u63a5',
  },
  'Pre-built content': {
    en: 'Pre-built content', de: 'Vorgefertigte Inhalte', es: 'Contenido predefinido', fr: "Contenu pr\u00eat \u00e0 l'emploi", it: 'Contenuti predefiniti',
    ja: '\u4e8b\u524d\u69cb\u7bc9\u30b3\u30f3\u30c6\u30f3\u30c4', ko: '\uc0ac\uc804 \uad6c\ucd95 \ucf58\ud150\uce20', ru: '\u0413\u043e\u0442\u043e\u0432\u044b\u0439 \u043a\u043e\u043d\u0442\u0435\u043d\u0442', zh: '\u9884\u7f6e\u5185\u5bb9',
  },
  'Try OpenCTI Enterprise Edition': {
    en: 'Try OpenCTI Enterprise Edition', de: 'OpenCTI Enterprise Edition testen', es: 'Probar OpenCTI Enterprise Edition', fr: 'Essayer OpenCTI Enterprise Edition', it: 'Prova OpenCTI Enterprise Edition',
    ja: 'OpenCTI Enterprise Edition\u3092\u8a66\u3059', ko: 'OpenCTI Enterprise Edition \uc0ac\uc6a9\ud574 \ubcf4\uae30', ru: '\u041f\u043e\u043f\u0440\u043e\u0431\u043e\u0432\u0430\u0442\u044c OpenCTI Enterprise Edition', zh: '\u8bd5\u7528 OpenCTI Enterprise Edition',
  },
  'XTM Platform free trial': {
    en: 'XTM Platform free trial', de: 'Kostenlose Testversion der XTM-Plattform', es: 'Prueba gratuita de la plataforma XTM', fr: 'Essai gratuit de la plateforme XTM', it: 'Prova gratuita della piattaforma XTM',
    ja: 'XTM\u30d7\u30e9\u30c3\u30c8\u30d5\u30a9\u30fc\u30e0\u7121\u6599\u30c8\u30e9\u30a4\u30a2\u30eb', ko: 'XTM \ud50c\ub7ab\ud3fc \ubb34\ub8cc \uccb4\ud5d8', ru: '\u0411\u0435\u0441\u043f\u043b\u0430\u0442\u043d\u0430\u044f \u043f\u0440\u043e\u0431\u043d\u0430\u044f \u0432\u0435\u0440\u0441\u0438\u044f \u043f\u043b\u0430\u0442\u0444\u043e\u0440\u043c\u044b XTM', zh: 'XTM \u5e73\u53f0\u514d\u8d39\u8bd5\u7528',
  },
  'XTM Platform Roadmap': {
    en: 'XTM Platform Roadmap', de: 'XTM-Plattform-Roadmap', es: 'Hoja de ruta de la plataforma XTM', fr: 'Feuille de route de la plateforme XTM', it: 'Roadmap della piattaforma XTM',
    ja: 'XTM\u30d7\u30e9\u30c3\u30c8\u30d5\u30a9\u30fc\u30e0\u30ed\u30fc\u30c9\u30de\u30c3\u30d7', ko: 'XTM \ud50c\ub7ab\ud3fc \ub85c\ub4dc\ub9f5', ru: '\u0414\u043e\u0440\u043e\u0436\u043d\u0430\u044f \u043a\u0430\u0440\u0442\u0430 \u043f\u043b\u0430\u0442\u0444\u043e\u0440\u043c\u044b XTM', zh: 'XTM \u5e73\u53f0\u8def\u7ebf\u56fe',
  },
};

const escapeJson = (value) => JSON.stringify(value);

for (const lang of ['en', 'de', 'es', 'fr', 'it', 'ja', 'ko', 'ru', 'zh']) {
  const file = `lang/front/${lang}.json`;
  const raw = readFileSync(file, 'utf8');
  const json = JSON.parse(raw);
  const missing = Object.keys(translations).filter((k) => !(k in json));
  if (missing.length === 0) continue;
  let lines = raw.replace(/\r\n/g, '\n').split('\n');
  for (const key of missing) {
    const newLine = `  ${escapeJson(key)}: ${escapeJson(translations[key][lang])},`;
    // Find the first existing key line that sorts after the new key
    // (files are sorted case-insensitively by key).
    let insertAt = -1;
    for (let i = 0; i < lines.length; i += 1) {
      const m = /^ {2}"((?:[^"\\]|\\.)*)":/.exec(lines[i]);
      if (!m) continue;
      const existingKey = JSON.parse(`"${m[1]}"`);
      if (existingKey.toLowerCase().localeCompare(key.toLowerCase(), 'en') > 0) {
        insertAt = i;
        break;
      }
    }
    if (insertAt === -1) throw new Error(`No insertion point for '${key}' in ${lang}`);
    lines.splice(insertAt, 0, newLine);
  }
  let output = lines.join('\n');
  // Normalize a trailing newline after the closing brace.
  output = `${output.replace(/\n*$/, '')}\n`;
  writeFileSync(file, output, 'utf8');
  JSON.parse(readFileSync(file, 'utf8')); // sanity: still valid JSON
  console.log(`${lang}: inserted ${missing.length} keys`);
}
