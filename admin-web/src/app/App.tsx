import { useEffect, useState } from 'react';
import { BrowserRouter, Navigate, Route, Routes } from 'react-router-dom';
import { Alert, Button, Card, ConfigProvider, Form, Input, Message, Modal, Popconfirm, Select, Space, Switch, Table, Tag, Typography } from '@arco-design/web-react';
import enUS from '@arco-design/web-react/es/locale/en-US';
import { AdminShell } from '../widgets/admin-shell';
import { request } from '../shared/api/request';
import { StoragePage } from '../pages/storage';
import { CallsPage, AccessPage } from '../pages/activity';

type Resource = { id: number; name: string; type?: string; enabled?: boolean; allow_anonymous?: boolean; proxy_id?: number; upstream_id?: number; prefix?: string; connection_ids?: number[]; expires_at?: string; settings?: string };
type Kind = 'connections' | 'proxies' | 'keys';
const connectionTypes = ['ssh', 'k8s', 'rdp', 'mongodb', 'redis', 'mysql', 'postgres', 'sqlite', 'https'];
const titles = { connections: 'Connections', proxies: 'Proxies', keys: 'API keys' };

function Login() {
 const [loading, setLoading] = useState(false);
 async function submit(values: Record<string, unknown>) {
  setLoading(true);
  try { const { data } = await request.post('/auth/login', values); sessionStorage.setItem('connkit.admin.token', data.data.token); window.location.assign('/connections'); }
  catch (error) { Message.error((error as Error).message); }
  finally { setLoading(false); }
 }
 return <div className="login-container"><Card className="login-card"><Typography.Title heading={3}>ConnKit Admin</Typography.Title><Typography.Paragraph>Sign in to manage connections and access keys.</Typography.Paragraph><Form layout="vertical" onSubmit={(values) => { void submit(values); }}><Form.Item field="username" label="Username" rules={[{ required: true }]}><Input autoComplete="username" /></Form.Item><Form.Item field="password" label="Password" rules={[{ required: true }]}><Input.Password autoComplete="current-password" /></Form.Item><Button htmlType="submit" type="primary" long loading={loading}>Sign in</Button></Form></Card></div>;
}

function ResourcePage({ kind }: { kind: Kind }) {
 const [rows, setRows] = useState<Resource[]>([]);
 const [connections, setConnections] = useState<Resource[]>([]);
 const [proxies, setProxies] = useState<Resource[]>([]);
 const [loading, setLoading] = useState(false);
 const [visible, setVisible] = useState(false);
 const [saving, setSaving] = useState(false);
 const [editing, setEditing] = useState<Resource>();
 const [revealed, setRevealed] = useState('');
 const [form] = Form.useForm();
 async function load() {
  setLoading(true);
  try {
   const [response, targets, routes] = await Promise.all([request.get(`/${kind}`), request.get('/connections'), request.get('/proxies')]);
   setRows(response.data.data); setConnections(targets.data.data); setProxies(routes.data.data);
  } catch (error) { Message.error((error as Error).message); }
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
    if (Number.isNaN(expires.getTime())) throw new Error('Enter a valid expiry timestamp');
    body.expires_at = expires.toISOString();
   } else { body.expires_at = null; }
   const response = editing ? await request.put(`/${kind}/${editing.id}`, body) : await request.post(`/${kind}`, body);
   if (kind === 'keys' && !editing) setRevealed(response.data.data.token);
   setVisible(false); await load();
  } catch (error) { Message.error((error as Error).message); }
  finally { setSaving(false); }
 }
 async function remove(row: Resource) { try { await request.delete(`/${kind}/${row.id}`); await load(); } catch (error) { Message.error((error as Error).message); } }
 const columns = [
  { title: 'ID', dataIndex: 'id', width: 70 }, { title: 'Name', dataIndex: 'name' },
  ...(kind === 'keys' ? [{ title: 'Prefix', dataIndex: 'prefix' }, { title: 'Connection IDs', render: (_: unknown, row: Resource) => row.connection_ids?.join(', ') || 'None' }] : [{ title: 'Type', dataIndex: 'type' }]),
  ...(kind !== 'proxies' ? [{ title: 'Status', render: (_: unknown, row: Resource) => <Tag color={row.enabled ? 'green' : 'gray'}>{row.enabled ? 'Enabled' : 'Disabled'}</Tag> }] : []),
  { title: 'Actions', width: 240, render: (_: unknown, row: Resource) => <Space><Button size="small" onClick={() => open(row)}>Edit</Button>{kind === 'connections' && <Button size="small" onClick={async () => { try { const { data } = await request.post(`/connections/${row.id}/test`); Modal.info({ title: 'Connection test', content: <pre style={{ whiteSpace: 'pre-wrap' }}>{JSON.stringify(data.data, null, 2)}</pre> }); } catch (e) { Message.error((e as Error).message); } }}>Test</Button>}<Popconfirm title={kind === 'keys' ? 'Revoke this key?' : 'Delete this configuration?'} onOk={() => remove(row)}><Button size="small" status="danger">{kind === 'keys' ? 'Revoke' : 'Delete'}</Button></Popconfirm></Space> }
 ];
 return <Card>
  <div className="page-toolbar"><Typography.Title heading={4} style={{ margin: 0 }}>{titles[kind]}</Typography.Title><Button type="primary" onClick={() => open()}>Create</Button></div>
  <Alert type="info" content="Configure protocol settings and routes, then test a connection. Writes and arbitrary commands require explicit opt-in. See docs/protocols.md for settings and tools." style={{ marginBottom: 20 }} />
  <Table rowKey="id" loading={loading} data={rows} columns={columns} scroll={{ x: 700 }} pagination={{ pageSize: 20 }} />
  <Modal title={`${editing ? 'Edit' : 'Create'} ${kind === 'keys' ? 'API key' : kind.slice(0, -1)}`} visible={visible} confirmLoading={saving} onCancel={() => setVisible(false)} onOk={save} unmountOnExit>
   <Form form={form} layout="vertical">
    <Form.Item field="name" label="Name" rules={[{ required: true }]}><Input maxLength={120} /></Form.Item>
    {kind === 'keys' ? <>
     <Form.Item field="enabled" label="Enabled" triggerPropName="checked"><Switch /></Form.Item>
     <Form.Item field="connection_ids" label="Allowed connections" extra="An empty selection grants access to no connections."><Select mode="multiple" options={connections.map((c) => ({ label: c.name, value: c.id }))} /></Form.Item>
     <Form.Item field="expires_at" label="Expiry (optional)" extra="ISO 8601, e.g. 2030-01-01T00:00:00Z"><Input /></Form.Item>
    </> : <>
     <Form.Item field="type" label="Type" rules={[{ required: true }]}><Select options={kind === 'connections' ? connectionTypes : ['http', 'https', 'socks5', 'ssh']} /></Form.Item>
     <Form.Item field={kind === 'connections' ? 'proxy_id' : 'upstream_id'} label={kind === 'connections' ? 'Proxy (optional)' : 'Upstream proxy (optional)'}><Select allowClear options={proxies.filter((p) => kind !== 'proxies' || p.id !== editing?.id).map((p) => ({ label: p.name, value: p.id }))} /></Form.Item>
     {kind === 'connections' && <><Form.Item field="enabled" label="Enabled" triggerPropName="checked"><Switch /></Form.Item><Form.Item field="allow_anonymous" label="Allow through anonymous MCP listener" triggerPropName="checked"><Switch /></Form.Item></>}
     <Form.Item field="settings" label="Protocol settings (JSON)" extra={editing ? 'Leave blank to preserve encrypted settings. Existing credentials are not returned.' : 'Settings are encrypted before storage. See docs/protocols.md for protocol fields.'}><Input.TextArea rows={6} autoComplete="off" /></Form.Item>
    </>}
   </Form>
  </Modal>
  <Modal title="Copy your API key" visible={Boolean(revealed)} footer={<Button type="primary" onClick={() => setRevealed('')}>Done</Button>} onCancel={() => setRevealed('')}><Typography.Paragraph>This key is shown once. Store it securely.</Typography.Paragraph><Input value={revealed} readOnly onFocus={(event) => event.target.select()} /></Modal>
 </Card>;
}

function Protected({ kind }: { kind: Kind | 'storage' | 'calls' | 'access' }) { return sessionStorage.getItem('connkit.admin.token') ? <AdminShell>{kind === 'storage' ? <StoragePage /> : kind === 'calls' ? <CallsPage /> : kind === 'access' ? <AccessPage /> : <ResourcePage key={kind} kind={kind} />}</AdminShell> : <Navigate to="/login" replace />; }
export function App() { return <ConfigProvider locale={enUS}><BrowserRouter><Routes><Route path="/login" element={<Login />} />{(['connections', 'proxies', 'keys', 'storage', 'calls', 'access'] as (Kind | 'storage' | 'calls' | 'access')[]).map((kind) => <Route key={kind} path={`/${kind}`} element={<Protected kind={kind} />} />)}<Route path="*" element={<Navigate to="/connections" replace />} /></Routes></BrowserRouter></ConfigProvider>; }
