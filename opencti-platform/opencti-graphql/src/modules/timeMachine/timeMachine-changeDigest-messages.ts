// The messages of a change digest, written in the language of each recipient.
// Counts take the plural rules of the language (Intl.PluralRules); the vocabulary is the one of the front language files.

interface PluralMessage extends Partial<Record<Intl.LDMLPluralRule, string>> {
  other: string;
  // The value whose plural form the message takes, `count` when not set
  by?: string;
}

type DigestMessage = string | PluralMessage;

export type ChangeDigestMessageKey = 'created' | 'revoked' | 'relationships_added' | 'relationships_removed' | 'relationships_revoked'
  | 'relationships_confidence_changed' | 'attributes_changed' | 'confidence' | 'score' | 'entities_changed' | 'revocations' | 'new_techniques' | 'new_malware' | 'new_tools'
  | 'new_infrastructure' | 'not_listed' | 'partial';

type DigestLanguage = 'en' | 'fr' | 'es' | 'de' | 'it' | 'ja' | 'ko' | 'zh' | 'ru';

const MESSAGES: Record<DigestLanguage, Record<ChangeDigestMessageKey, DigestMessage>> = {
  en: {
    created: 'created',
    revoked: 'revoked',
    relationships_added: { one: '{count} new relationship', other: '{count} new relationships' },
    relationships_removed: { one: '{count} removed relationship', other: '{count} removed relationships' },
    relationships_revoked: { one: '{count} revoked relationship', other: '{count} revoked relationships' },
    relationships_confidence_changed: { one: '{count} confidence change on relationships', other: '{count} confidence changes on relationships' },
    attributes_changed: { one: '{count} attribute changed', other: '{count} attributes changed' },
    confidence: 'confidence {before} -> {after}',
    score: 'score {before} -> {after}',
    entities_changed: { by: 'total', one: '{changed} of {total} entity changed', other: '{changed} of {total} entities changed' },
    revocations: { one: '{count} revocation', other: '{count} revocations' },
    new_techniques: { one: '{count} new technique', other: '{count} new techniques' },
    new_malware: '{count} new malware',
    new_tools: { one: '{count} new tool', other: '{count} new tools' },
    new_infrastructure: '{count} new infrastructure',
    not_listed: { one: '{count} other changed entity not listed', other: '{count} other changed entities not listed' },
    partial: 'partial result: the filter set exceeds the limits of a change digest, only its most recent entities and relationships are compared',
  },
  fr: {
    created: 'création',
    revoked: 'révocation',
    relationships_added: { one: '{count} nouvelle relation', other: '{count} nouvelles relations' },
    relationships_removed: { one: '{count} relation supprimée', other: '{count} relations supprimées' },
    relationships_revoked: { one: '{count} relation révoquée', other: '{count} relations révoquées' },
    relationships_confidence_changed: { one: '{count} changement de confiance des relations', other: '{count} changements de confiance des relations' },
    attributes_changed: { one: '{count} attribut modifié', other: '{count} attributs modifiés' },
    confidence: 'confiance {before} -> {after}',
    score: 'score {before} -> {after}',
    entities_changed: { by: 'changed', one: '{changed} entité modifiée sur {total}', other: '{changed} entités modifiées sur {total}' },
    revocations: { one: '{count} révocation', other: '{count} révocations' },
    new_techniques: { one: '{count} nouvelle technique', other: '{count} nouvelles techniques' },
    new_malware: { one: '{count} nouveau malware', other: '{count} nouveaux malwares' },
    new_tools: { one: '{count} nouvel outil', other: '{count} nouveaux outils' },
    new_infrastructure: { one: '{count} nouvelle infrastructure', other: '{count} nouvelles infrastructures' },
    not_listed: { one: '{count} autre entité modifiée non listée', other: '{count} autres entités modifiées non listées' },
    partial: 'résultat partiel : le jeu de filtres dépasse les limites d\'un résumé des changements, seules ses entités et relations les plus récentes sont comparées',
  },
  es: {
    created: 'creación',
    revoked: 'revocación',
    relationships_added: { one: '{count} nueva relación', other: '{count} nuevas relaciones' },
    relationships_removed: { one: '{count} relación eliminada', other: '{count} relaciones eliminadas' },
    relationships_revoked: { one: '{count} relación revocada', other: '{count} relaciones revocadas' },
    relationships_confidence_changed: { one: '{count} cambio de confianza en relaciones', other: '{count} cambios de confianza en relaciones' },
    attributes_changed: { one: '{count} atributo modificado', other: '{count} atributos modificados' },
    confidence: 'confianza {before} -> {after}',
    score: 'puntuación {before} -> {after}',
    entities_changed: { by: 'changed', one: '{changed} entidad modificada de {total}', other: '{changed} entidades modificadas de {total}' },
    revocations: { one: '{count} revocación', other: '{count} revocaciones' },
    new_techniques: { one: '{count} nueva técnica', other: '{count} nuevas técnicas' },
    new_malware: { one: '{count} nuevo malware', other: '{count} nuevos malware' },
    new_tools: { one: '{count} nueva herramienta', other: '{count} nuevas herramientas' },
    new_infrastructure: { one: '{count} nueva infraestructura', other: '{count} nuevas infraestructuras' },
    not_listed: { one: '{count} otra entidad modificada no listada', other: '{count} otras entidades modificadas no listadas' },
    partial: 'resultado parcial: el conjunto de filtros supera los límites de un resumen de cambios, solo se comparan sus entidades y relaciones más recientes',
  },
  de: {
    created: 'erstellt',
    revoked: 'widerrufen',
    relationships_added: { one: '{count} neue Beziehung', other: '{count} neue Beziehungen' },
    relationships_removed: { one: '{count} entfernte Beziehung', other: '{count} entfernte Beziehungen' },
    relationships_revoked: { one: '{count} widerrufene Beziehung', other: '{count} widerrufene Beziehungen' },
    relationships_confidence_changed: { one: '{count} Konfidenzänderung an Beziehungen', other: '{count} Konfidenzänderungen an Beziehungen' },
    attributes_changed: { one: '{count} Attribut geändert', other: '{count} Attribute geändert' },
    confidence: 'Konfidenz {before} -> {after}',
    score: 'Score {before} -> {after}',
    entities_changed: { by: 'total', one: '{changed} von {total} Entität geändert', other: '{changed} von {total} Entitäten geändert' },
    revocations: { one: '{count} Widerruf', other: '{count} Widerrufe' },
    new_techniques: { one: '{count} neue Technik', other: '{count} neue Techniken' },
    new_malware: '{count} neue Malware',
    new_tools: { one: '{count} neues Tool', other: '{count} neue Tools' },
    new_infrastructure: { one: '{count} neue Infrastruktur', other: '{count} neue Infrastrukturen' },
    not_listed: { one: '{count} weitere geänderte Entität nicht aufgeführt', other: '{count} weitere geänderte Entitäten nicht aufgeführt' },
    partial: 'Teilergebnis: Der Filtersatz überschreitet die Grenzen einer Änderungsübersicht, nur seine neuesten Entitäten und Beziehungen werden verglichen',
  },
  it: {
    created: 'creazione',
    revoked: 'revoca',
    relationships_added: { one: '{count} nuova relazione', other: '{count} nuove relazioni' },
    relationships_removed: { one: '{count} relazione rimossa', other: '{count} relazioni rimosse' },
    relationships_revoked: { one: '{count} relazione revocata', other: '{count} relazioni revocate' },
    relationships_confidence_changed: { one: '{count} modifica di confidenza sulle relazioni', other: '{count} modifiche di confidenza sulle relazioni' },
    attributes_changed: { one: '{count} attributo modificato', other: '{count} attributi modificati' },
    confidence: 'confidenza {before} -> {after}',
    score: 'punteggio {before} -> {after}',
    entities_changed: { by: 'changed', one: '{changed} entità modificata su {total}', other: '{changed} entità modificate su {total}' },
    revocations: { one: '{count} revoca', other: '{count} revoche' },
    new_techniques: { one: '{count} nuova tecnica', other: '{count} nuove tecniche' },
    new_malware: { one: '{count} nuovo malware', other: '{count} nuovi malware' },
    new_tools: { one: '{count} nuovo strumento', other: '{count} nuovi strumenti' },
    new_infrastructure: { one: '{count} nuova infrastruttura', other: '{count} nuove infrastrutture' },
    not_listed: { one: '{count} altra entità modificata non elencata', other: '{count} altre entità modificate non elencate' },
    partial: 'risultato parziale: il set di filtri supera i limiti di un riepilogo delle modifiche, vengono confrontate solo le sue entità e relazioni più recenti',
  },
  ja: {
    created: '作成',
    revoked: '失効',
    relationships_added: '{count} 件の新しいリレーションシップ',
    relationships_removed: '{count} 件の削除されたリレーションシップ',
    relationships_revoked: '{count} 件の失効したリレーションシップ',
    relationships_confidence_changed: '{count} 件のリレーションシップの信頼度の変更',
    attributes_changed: '{count} 件の属性を変更',
    confidence: '信頼度 {before} -> {after}',
    score: 'スコア {before} -> {after}',
    entities_changed: '{total} 件中 {changed} 件のエンティティを変更',
    revocations: '{count} 件の失効',
    new_techniques: '{count} 件の新しいテクニック',
    new_malware: '{count} 件の新しいマルウェア',
    new_tools: '{count} 件の新しいツール',
    new_infrastructure: '{count} 件の新しいインフラストラクチャ',
    not_listed: '一覧にないその他の変更されたエンティティ {count} 件',
    partial: '部分的な結果: フィルターセットが変更ダイジェストの上限を超えているため、最新のエンティティとリレーションシップのみを比較しています',
  },
  ko: {
    created: '생성됨',
    revoked: '철회됨',
    relationships_added: '새 관계 {count}개',
    relationships_removed: '제거된 관계 {count}개',
    relationships_revoked: '철회된 관계 {count}개',
    relationships_confidence_changed: '관계의 신뢰도 변경 {count}건',
    attributes_changed: '속성 {count}개 변경됨',
    confidence: '신뢰도 {before} -> {after}',
    score: '점수 {before} -> {after}',
    entities_changed: '엔터티 {total}개 중 {changed}개 변경됨',
    revocations: '철회 {count}건',
    new_techniques: '새 기법 {count}개',
    new_malware: '새 악성코드 {count}개',
    new_tools: '새 도구 {count}개',
    new_infrastructure: '새 인프라 {count}개',
    not_listed: '목록에 없는 기타 변경된 엔터티 {count}개',
    partial: '부분 결과: 필터 세트가 변경 다이제스트의 한도를 초과하여 가장 최근의 엔터티와 관계만 비교합니다',
  },
  zh: {
    created: '已创建',
    revoked: '已撤销',
    relationships_added: '{count} 个新关系',
    relationships_removed: '{count} 个已移除的关系',
    relationships_revoked: '{count} 个已撤销的关系',
    relationships_confidence_changed: '{count} 次关系的置信度变化',
    attributes_changed: '{count} 个属性已更改',
    confidence: '置信度 {before} -> {after}',
    score: '评分 {before} -> {after}',
    entities_changed: '{total} 个实体中有 {changed} 个已更改',
    revocations: '{count} 次撤销',
    new_techniques: '{count} 个新技术',
    new_malware: '{count} 个新恶意软件',
    new_tools: '{count} 个新工具',
    new_infrastructure: '{count} 个新基础设施',
    not_listed: '另有 {count} 个已更改的实体未列出',
    partial: '部分结果：筛选条件集超出了变更摘要的限制，仅比较其最新的实体和关系',
  },
  ru: {
    created: 'создание',
    revoked: 'отзыв',
    relationships_added: { one: '{count} новая связь', few: '{count} новые связи', many: '{count} новых связей', other: '{count} новой связи' },
    relationships_removed: { one: '{count} удалённая связь', few: '{count} удалённые связи', many: '{count} удалённых связей', other: '{count} удалённой связи' },
    relationships_revoked: { one: '{count} отозванная связь', few: '{count} отозванные связи', many: '{count} отозванных связей', other: '{count} отозванной связи' },
    relationships_confidence_changed: { one: '{count} изменение уровня доверия связей', few: '{count} изменения уровня доверия связей', many: '{count} изменений уровня доверия связей', other: '{count} изменения уровня доверия связей' },
    attributes_changed: { one: '{count} атрибут изменён', few: '{count} атрибута изменено', many: '{count} атрибутов изменено', other: '{count} атрибута изменено' },
    confidence: 'уверенность {before} -> {after}',
    score: 'оценка {before} -> {after}',
    entities_changed: 'изменено сущностей: {changed} из {total}',
    revocations: { one: '{count} отзыв', few: '{count} отзыва', many: '{count} отзывов', other: '{count} отзыва' },
    new_techniques: { one: '{count} новая техника', few: '{count} новые техники', many: '{count} новых техник', other: '{count} новой техники' },
    new_malware: 'новое вредоносное ПО: {count}',
    new_tools: { one: '{count} новый инструмент', few: '{count} новых инструмента', many: '{count} новых инструментов', other: '{count} нового инструмента' },
    new_infrastructure: 'новая инфраструктура: {count}',
    not_listed: { one: 'ещё {count} изменённая сущность не показана', few: 'ещё {count} изменённые сущности не показаны', many: 'ещё {count} изменённых сущностей не показано', other: 'ещё {count} изменённой сущности не показано' },
    partial: 'частичный результат: набор фильтров превышает ограничения сводки изменений, сравниваются только его самые последние сущности и связи',
  },
};

export interface ChangeDigestLocale {
  language: DigestLanguage;
  // BCP 47 tag used for plural rules, numbers and lists
  locale: string;
}

export const DEFAULT_CHANGE_DIGEST_LOCALE: ChangeDigestLocale = { language: 'en', locale: 'en-us' };

const isDigestLanguage = (language: string): language is DigestLanguage => Object.keys(MESSAGES).includes(language);

/**
 * The language of a change digest: the language of the recipient's profile, else the platform language, else English.
 * Languages are stored as `fr-fr`, `zh-cn`...; `auto` follows the browser, which a digest does not have.
 */
export const resolveChangeDigestLocale = (userLanguage?: string | null, platformLanguage?: string | null): ChangeDigestLocale => {
  const chosen = [userLanguage, platformLanguage].find((language) => language && language !== 'auto' && isDigestLanguage(language.substring(0, 2).toLowerCase()));
  if (!chosen) return DEFAULT_CHANGE_DIGEST_LOCALE;
  return { language: chosen.substring(0, 2).toLowerCase() as DigestLanguage, locale: chosen };
};

// Values are counts and scores, rendered as code in the Markdown of the notification
export const formatChangeDigestMessage = (target: ChangeDigestLocale, key: ChangeDigestMessageKey, values: Record<string, number> = {}): string => {
  const message = MESSAGES[target.language][key];
  const template = typeof message === 'string'
    ? message
    : (message[new Intl.PluralRules(target.locale).select(values[message.by ?? 'count'] ?? 0)] ?? message.other);
  const numbers = new Intl.NumberFormat(target.locale);
  return template.replace(/\{(\w+)\}/g, (placeholder, name: string) => (name in values ? `\`${numbers.format(values[name])}\`` : placeholder));
};

export const joinChangeDigestParts = (target: ChangeDigestLocale, parts: string[]): string => {
  return new Intl.ListFormat(target.locale, { type: 'conjunction' }).format(parts);
};
