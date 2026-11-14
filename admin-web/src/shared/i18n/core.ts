import { zhCN, type MessageKey } from './messages';
export type Locale = 'zh-CN' | 'en-US';
function detectLocale(): Locale {
 try {
  const saved = localStorage.getItem('connkit.locale');
  if (saved === 'zh-CN' || saved === 'en-US') return saved;
 } catch { /* Storage may be disabled by the browser. */ }
 if (typeof navigator !== 'undefined') return navigator.language.toLowerCase().startsWith('zh') ? 'zh-CN' : 'en-US';
 return 'zh-CN';
}
let currentLocale = detectLocale();
export function getLocale() { return currentLocale; }
export function setLocale(locale: Locale) {
 currentLocale = locale;
 try { localStorage.setItem('connkit.locale', locale); } catch { /* In-memory switching still works. */ }
}
export function translate(key: MessageKey, values: Record<string, string | number> = {}, locale = currentLocale): string {
 const message: string = locale === 'zh-CN' ? zhCN[key] : key;
 return message.replace(/\{(\w+)\}/g, (placeholder, name: string) => Object.hasOwn(values, name) ? String(values[name]) : placeholder);
}
export function errorMessage(error: unknown): string {
 if (error instanceof SyntaxError) return translate('Enter valid JSON settings');
 const raw = error instanceof Error ? error.message : typeof error === 'string' ? error : 'Request failed';
 if (/timeout|timed out/i.test(raw)) return translate('Request timed out');
 if (Object.hasOwn(zhCN, raw)) return translate(raw as MessageKey);
 // Preserve unknown diagnostic detail instead of replacing it with a false explanation.
 return raw || translate('Request failed');
}
const statusKeys: Record<string, MessageKey> = { running: 'Running', success: 'Success', error: 'Error', unknown: 'Unknown', prepared: 'Prepared', delivering: 'Delivering', delivered: 'Delivered', removing: 'Removing', removed: 'Removed' };
export function statusLabel(status: string, locale = currentLocale): string { return statusKeys[status] ? translate(statusKeys[status], {}, locale) : status; }
