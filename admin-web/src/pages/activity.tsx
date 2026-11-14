import { useI18n } from '../shared/i18n';
import { errorMessage, statusLabel } from '../shared/i18n/core';
import { useEffect, useState } from 'react';
import { Alert, Button, Card, Form, Input, Message, Table, Typography } from '@arco-design/web-react';
import { request } from '../shared/api/request';
type Call = { id: number; actor: string; connection_id: number; tool: string; status: string; duration_ms: number; created_at: string };
export function CallsPage() {
 const { t, locale } = useI18n();
 const [rows, setRows] = useState<Call[]>([]);
 const [loading, setLoading] = useState(false);
 const [more, setMore] = useState(false);
 async function load(before?: number) {
  setLoading(true);
  try { const { data } = await request.get('/calls', { params: before ? { before } : {} }); const next: Call[] = data.data; setRows((old) => before ? [...old, ...next] : next); setMore(next.length === 100); }
  catch (e) { Message.error(errorMessage(e)); } finally { setLoading(false); }
 }
 useEffect(() => { void load(); }, []);
 return <Card><div className="page-toolbar"><Typography.Title heading={4}>{t('Tool calls')}</Typography.Title><Button loading={loading} onClick={() => { void load(); }}>{t('Refresh')}</Button></div><Alert content={t('Metadata only. A running or unknown call may have completed on the target. Inspect the target before retrying a mutation.')} /><Table rowKey="id" data={rows} loading={loading} pagination={false} columns={[
   { title: t('ID'), dataIndex: 'id' },
   { title: t('Time'), dataIndex: 'created_at', render: (value: string) => new Date(value).toLocaleString(locale) },
   { title: t('Actor'), dataIndex: 'actor', render: (value: string) => value === 'admin' ? t('Administrator') : value === 'anonymous' ? t('Anonymous') : value.startsWith('key:') ? t('Key #{id}', { id: value.slice(4) }) : value },
   { title: t('Connection'), dataIndex: 'connection_id' },
   { title: t('Tool'), dataIndex: 'tool' },
   { title: t('Status'), dataIndex: 'status', render: (value: string) => statusLabel(value, locale) },
   { title: t('Duration (ms)'), dataIndex: 'duration_ms' },
  ]} scroll={{ x: 1000 }} />{more && <Button loading={loading} onClick={() => { void load(rows[rows.length - 1]?.id); }}>{t('Load older calls')}</Button>}</Card>;
}
export function AccessPage() {
 const { t } = useI18n();
 const [cidrs, setCIDRs] = useState('');
 const [saving, setSaving] = useState(false);
 useEffect(() => { request.get('/access').then(({ data }) => setCIDRs((data.data.anonymous_cidrs || []).join('\n'))).catch((e: Error) => Message.error(errorMessage(e))); }, []);
 async function save() { setSaving(true); try { await request.put('/access', { anonymous_cidrs: cidrs.split(/[\s,]+/).filter(Boolean) }); Message.success(t('Access policy saved')); } catch (e) { Message.error(errorMessage(e)); } finally { setSaving(false); } }
 return <Card><Typography.Title heading={4}>{t('Anonymous listener access')}</Typography.Title><Alert content={t('Rules apply to the immediate TCP peer. Environment CIDRs also apply. An empty list adds no restriction; protect the anonymous port with network access controls.')} /><Form layout="vertical"><Form.Item label={t('Allowed source CIDRs')} extra={t('One CIDR per line, for example 10.0.0.0/8 or 127.0.0.1/32.')}><Input.TextArea rows={8} value={cidrs} onChange={setCIDRs} /></Form.Item><Button type="primary" loading={saving} onClick={() => { void save(); }}>{t('Save policy')}</Button></Form></Card>;
}
