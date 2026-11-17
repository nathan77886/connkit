import { I18nProvider, LanguageSelect, useI18n, useFormLanguage } from '../shared/i18n';
import { errorMessage } from '../shared/i18n/core';
import { useEffect, useState } from 'react';
import { BrowserRouter, Navigate, Route, Routes } from 'react-router-dom';
import { Alert, Button, Card, Form, Input, Message, Modal, Popconfirm, Select, Space, Switch, Table, Tag, Typography } from '@arco-design/web-react';
import { AdminShell } from '../widgets/admin-shell';
import { request } from '../shared/api/request';
import { StoragePage } from '../pages/storage';
import { CallsPage, AccessPage } from '../pages/activity';
import { CloudflareAuthorization, CloudflareCallback } from '../pages/cloudflare';

type Resource = { id: number; name: string; type?: string; enabled?: boolean; allow_anonymous?: boolean; proxy_id?: number; upstream_id?: number; prefix?: string; connection_ids?: number[]; expires_at?: string; settings?: string };
type Kind = 'connections' | 'proxies' | 'keys';
const connectionTypes = ['ssh', 'k8s', 'rdp', 'mongodb', 'redis', 'mysql', 'postgres', 'sqlite', 'https', 'onepanel', 'cloudflare_mcp'];

function Login() {
 const { t } = useI18n();
 const [form] = Form.useForm();
 useFormLanguage(form);
 const [loading, setLoading] = useState(false);
 async function submit(values: Record<string, unknown>) {
  setLoading(true);
  try { const { data } = await request.post('/auth/login', values); sessionStorage.setItem('connkit.admin.token', data.data.token); window.location.assign('/connections'); }
  catch (error) { Message.error(errorMessage(error)); }
  finally { setLoading(false); }
 }
 return <div className="login-container"><Card className="login-card"><div className="language-toolbar"><LanguageSelect /></div><Typography.Title heading={3}>{t('ConnKit Admin')}</Typography.Title><Typography.Paragraph>{t('Sign in to manage connections and access keys.')}</Typography.Paragraph><Form form={form} layout="vertical" onSubmit={(values) => { void submit(values); }}><Form.Item field="username" label={t('Username')} rules={[{ required: true }]}><Input autoComplete="username" /></Form.Item><Form.Item field="password" label={t('Password')} rules={[{ required: true }]}><Input.Password autoComplete="current-password" /></Form.Item><Button htmlType="submit" type="primary" long loading={loading}>{t('Sign in')}</Button></Form></Card></div>;
}

function ResourcePage({ kind }: { kind: Kind }) {
 const { t } = useI18n();
 const titles = { connections: t('Connections'), proxies: t('Proxies'), keys: t('API keys') };
 const [rows, setRows] = useState<Resource[]>([]);
 const [connections, setConnections] = useState<Resource[]>([]);
 const [proxies, setProxies] = useState<Resource[]>([]);
 const [loading, setLoading] = useState(false);
 const [visible, setVisible] = useState(false);
 const [saving, setSaving] = useState(false);
 const [editing, setEditing] = useState<Resource>();
 const [revealed, setRevealed] = useState('');
 const [oauthID, setOAuthID] = useState<number>();
 const [form] = Form.useForm();
 useFormLanguage(form);
 async function load() {
  setLoading(true);
  try {
   const [response, targets, routes] = await Promise.all([request.get(`/${kind}`), request.get('/connections'), request.get('/proxies')]);
   setRows(response.data.data); setConnections(targets.data.data); setProxies(routes.data.data);
  } catch (error) { Message.error(errorMessage(error)); }
  finally { setLoading(false); }
 }
 useEffect(() => { void load(); }, [kind]); // Pages are keyed by resource kind.
 function open(row?: Resource) { setEditing(row); form.resetFields(); form.setFieldsValue(row ? { ...row, settings: '', expires_at: row.expires_at || '' } : { enabled: true, allow_anonymous: false, connection_ids: [], settings: '{}' }); setVisible(true); }
 async function save() {
  const values = await form.validate();
  setSaving(true);
  try {
   const body = { ...values };
   if (kind !== 'keys') {
    if (body.settings?.trim()) body.settings = JSON.parse(body.settings); else delete body.settings;
    body.proxy_id = body.proxy_id || null; body.upstream_id = body.upstream_id || null;
   } else if (body.expires_at) {
    const expires = new Date(body.expires_at);
    if (Number.isNaN(expires.getTime())) throw new Error(t('Enter a valid expiry timestamp'));
    body.expires_at = expires.toISOString();
   } else { body.expires_at = null; }
   const response = editing ? await request.put(`/${kind}/${editing.id}`, body) : await request.post(`/${kind}`, body);
   if (kind === 'keys' && !editing) setRevealed(response.data.data.token);
   setVisible(false); await load();
  } catch (error) { Message.error(errorMessage(error)); }
  finally { setSaving(false); }
 }
 async function remove(row: Resource) { try { await request.delete(`/${kind}/${row.id}`); await load(); } catch (error) { Message.error(errorMessage(error)); } }
 const columns = [
  { title: t('ID'), dataIndex: 'id', width: 70 }, { title: t('Name'), dataIndex: 'name' },
  ...(kind === 'keys' ? [{ title: t('Prefix'), dataIndex: 'prefix' }, { title: t('Connection IDs'), render: (_: unknown, row: Resource) => row.connection_ids?.join(', ') || t('None') }] : [{ title: t('Type'), dataIndex: 'type' }]),
  ...(kind !== 'proxies' ? [{ title: t('Status'), render: (_: unknown, row: Resource) => <Tag color={row.enabled ? 'green' : 'gray'}>{row.enabled ? t('Enabled') : t('Disabled')}</Tag> }] : []),
  { title: t('Actions'), width: 320, render: (_: unknown, row: Resource) => <Space><Button size="small" onClick={() => open(row)}>{t('Edit')}</Button>{kind === 'connections' && row.type === 'cloudflare_mcp' && <Button size="small" onClick={() => setOAuthID(row.id)}>{t('Authorize')}</Button>}{kind === 'connections' && <Button size="small" onClick={async () => { try { const { data } = await request.post(`/connections/${row.id}/test`, {}, { timeout: 40000 }); Modal.info({ title: t('Connection test'), okText: t('Done'), content: <pre style={{ whiteSpace: 'pre-wrap' }}>{JSON.stringify(data.data, null, 2)}</pre> }); } catch (e) { Message.error(errorMessage(e)); } }}>{t('Test')}</Button>}<Popconfirm title={kind === 'keys' ? t('Revoke this key?') : t('Delete this configuration?')} onOk={() => remove(row)}><Button size="small" status="danger">{kind === 'keys' ? t('Revoke') : t('Delete')}</Button></Popconfirm></Space> }
 ];
 return <Card>
  {oauthID !== undefined && <CloudflareAuthorization id={oauthID} onClose={() => setOAuthID(undefined)} />}
  <div className="page-toolbar"><Typography.Title heading={4} style={{ margin: 0 }}>{titles[kind]}</Typography.Title><Button type="primary" onClick={() => open()}>{t('Create')}</Button></div>
  <Alert type="info" content={t('Configure protocol settings and routes, then test a connection. Writes and arbitrary commands require explicit opt-in. See docs/protocols.md for settings and tools.')} style={{ marginBottom: 20 }} />
  <Table rowKey="id" loading={loading} data={rows} columns={columns} scroll={{ x: 700 }} pagination={{ pageSize: 20 }} />
  <Modal title={t(editing ? 'Edit {resource}' : 'Create {resource}', { resource: t(kind === 'keys' ? 'API key' : kind === 'connections' ? 'connection' : 'proxy') })} visible={visible} confirmLoading={saving} onCancel={() => setVisible(false)} onOk={save} unmountOnExit>
   <Form form={form} layout="vertical">
    <Form.Item field="name" label={t('Name')} rules={[{ required: true }]}><Input maxLength={120} /></Form.Item>
    {kind === 'keys' ? <>
     <Form.Item field="enabled" label={t('Enable')} triggerPropName="checked"><Switch /></Form.Item>
     <Form.Item field="connection_ids" label={t('Allowed connections')} extra={t('An empty selection grants access to no connections.')}><Select mode="multiple" options={connections.map((c) => ({ label: c.name, value: c.id }))} /></Form.Item>
     <Form.Item field="expires_at" label={t('Expiry (optional)')} extra={t('ISO 8601, e.g. 2030-01-01T00:00:00Z')}><Input /></Form.Item>
    </> : <>
     <Form.Item field="type" label={t('Type')} rules={[{ required: true }]}><Select options={kind === 'connections' ? connectionTypes : ['http', 'https', 'socks5', 'ssh']} onChange={(type) => { if (type === 'cloudflare_mcp' && !editing) form.setFieldValue('settings', '{"allow_write":false,"allow_exec":false}'); }} /></Form.Item>
     {kind === 'connections' && <Form.Item noStyle shouldUpdate={(previous, current) => previous.type !== current.type}>{(values) => values.type === 'cloudflare_mcp' ? <Alert type="info" content={t('Save this connection, then click Authorize. No API token is needed. MCP tool calls require allow_write and allow_exec in settings.')} style={{ marginBottom: 16 }} /> : null}</Form.Item>}
     <Form.Item field={kind === 'connections' ? 'proxy_id' : 'upstream_id'} label={kind === 'connections' ? t('Proxy (optional)') : t('Upstream proxy (optional)')}><Select allowClear options={proxies.filter((p) => kind !== 'proxies' || p.id !== editing?.id).map((p) => ({ label: p.name, value: p.id }))} /></Form.Item>
     {kind === 'connections' && <><Form.Item field="enabled" label={t('Enable')} triggerPropName="checked"><Switch /></Form.Item><Form.Item field="allow_anonymous" label={t('Allow through anonymous MCP listener')} triggerPropName="checked"><Switch /></Form.Item></>}
     <Form.Item field="settings" label={t('Protocol settings (JSON)')} extra={editing ? t('Leave blank to preserve encrypted settings. Existing credentials are not returned.') : t('Settings are encrypted before storage. See docs/protocols.md for protocol fields.')}><Input.TextArea rows={6} autoComplete="off" /></Form.Item>
    </>}
   </Form>
  </Modal>
  <Modal title={t('Copy your API key')} visible={Boolean(revealed)} footer={<Button type="primary" onClick={() => setRevealed('')}>{t('Done')}</Button>} onCancel={() => setRevealed('')}><Typography.Paragraph>{t('This key is shown once. Store it securely.')}</Typography.Paragraph><Input value={revealed} readOnly onFocus={(event) => event.target.select()} /></Modal>
 </Card>;
}

function Protected({ kind }: { kind: Kind | 'storage' | 'calls' | 'access' }) { return sessionStorage.getItem('connkit.admin.token') ? <AdminShell>{kind === 'storage' ? <StoragePage /> : kind === 'calls' ? <CallsPage /> : kind === 'access' ? <AccessPage /> : <ResourcePage key={kind} kind={kind} />}</AdminShell> : <Navigate to="/login" replace />; }
export function App() { return <I18nProvider><BrowserRouter><Routes><Route path="/login" element={<Login />} /><Route path="/oauth/cloudflare/callback" element={<CloudflareCallback />} />{(['connections', 'proxies', 'keys', 'storage', 'calls', 'access'] as (Kind | 'storage' | 'calls' | 'access')[]).map((kind) => <Route key={kind} path={`/${kind}`} element={<Protected kind={kind} />} />)}<Route path="*" element={<Navigate to="/connections" replace />} /></Routes></BrowserRouter></I18nProvider>; }
