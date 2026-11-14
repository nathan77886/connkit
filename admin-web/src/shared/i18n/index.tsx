import { createContext, useContext, useEffect, useRef, useState, type PropsWithChildren } from 'react';
import type { FormInstance } from '@arco-design/web-react';
import { ConfigProvider, Select } from '@arco-design/web-react';
import enUS from '@arco-design/web-react/es/locale/en-US';
import zhCN from '@arco-design/web-react/es/locale/zh-CN';
import { getLocale, setLocale as saveLocale, translate, type Locale } from './core';
import type { MessageKey } from './messages';

type I18n = { locale: Locale; setLocale: (locale: Locale) => void; t: (key: MessageKey, values?: Record<string, string | number>) => string };
const Context = createContext<I18n | null>(null);
export function I18nProvider({ children }: PropsWithChildren) {
 const [locale, setLanguage] = useState<Locale>(getLocale);
 function setLocale(value: Locale) { saveLocale(value); setLanguage(value); }
 useEffect(() => {
  document.documentElement.lang = locale;
  document.title = translate('ConnKit Admin', {}, locale);
 }, [locale]);
 return <Context.Provider value={{ locale, setLocale, t: (key, values) => translate(key, values) }}><ConfigProvider locale={locale === 'zh-CN' ? zhCN : enUS}>{children}</ConfigProvider></Context.Provider>;
}
export function useI18n() { const context = useContext(Context); if (!context) throw new Error('I18nProvider is required'); return context; }
export function LanguageSelect() {
 const { locale, setLocale, t } = useI18n();
 return <Select aria-label={t('Language')} value={locale} onChange={setLocale} style={{ width: 128 }} options={[{ label: '简体中文', value: 'zh-CN' }, { label: 'English', value: 'en-US' }]} />;
}

// Refresh existing validation errors without resetting drafts on language changes.
export function useFormLanguage(form: FormInstance) {
 const { locale } = useI18n();
 const previous = useRef(locale);
 useEffect(() => {
  if (previous.current === locale) return;
  previous.current = locale;
  const fields = Object.entries(form.getFieldsError()).filter(([, error]) => Boolean(error)).map(([field]) => field);
  if (fields.length) void form.validate(fields).catch(() => undefined);
 }, [form, locale]);
}
