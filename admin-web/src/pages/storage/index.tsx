import { useEffect, useRef, useState } from 'react';
import { Alert, Button, Card, Form, Input, InputNumber, Message, Popconfirm, Select, Space, Switch, Table, Tag, Typography } from '@arco-design/web-react';
import { createSHA256 } from 'hash-wasm';
import { request } from '../../shared/api/request';

type Connection = { id: number; name: string; type: string; enabled: boolean };
type Transfer = { id: string; name: string; destination: string; status: string; connection_id: number; size: number };
type Grant = { file: Transfer; upload: { url: string; method: string; headers: Record<string, string[]> } };

export function StoragePage() {
 const [configForm] = Form.useForm();
 const [uploadForm] = Form.useForm();
 const [configured, setConfigured] = useState(false);
 const [saving, setSaving] = useState(false);
 const [busy, setBusy] = useState(false);
 const [phase, setPhase] = useState('');
 const [file, setFile] = useState<File>();
 const [connections, setConnections] = useState<Connection[]>([]);
 const [proxies, setProxies] = useState<{ id: number; name: string }[]>([]);
 const [transfers, setTransfers] = useState<Transfer[]>([]);
 const active = useRef<AbortController | null>(null);
 async function refresh() { const response = await request.get('/files'); setTransfers(response.data.data); }
 useEffect(() => {
  let cancelled = false;
  void Promise.all([request.get('/storage'), request.get('/connections'), request.get('/proxies'), request.get('/files')]).then(([storage, targets, routes, history]) => {
   if (cancelled) return;
   setConfigured(storage.data.data.configured);
   configForm.setFieldsValue(storage.data.data.config || { enabled: true, region: 'us-east-1', prefix: 'connkit', force_path_style: true, max_file_size_mb: 512 });
   setConnections(targets.data.data.filter((target: Connection) => target.type === 'ssh' && target.enabled));
   setProxies(routes.data.data); setTransfers(history.data.data);
  }).catch((error: Error) => { if (!cancelled) Message.error(error.message); });
  return () => { cancelled = true; active.current?.abort(); };
 }, [configForm]);
 async function save() {
  const values = await configForm.validate(); setSaving(true);
  try { await request.put('/storage', { ...values, proxy_id: values.proxy_id || null }); setConfigured(true); configForm.setFieldsValue({ access_key: '', secret_key: '', session_token: '', clear_session_token: false }); Message.success('Cloud storage configuration saved'); }
  catch (error) { Message.error((error as Error).message); }
  finally { setSaving(false); }
 }
 async function upload() {
  if (!file || file.size === 0) { Message.error('Select a non-empty file'); return; }
  const values = await uploadForm.validate();
  setBusy(true); const controller = new AbortController(); active.current = controller;
  let prepared: Grant | undefined;
  try {
   setPhase('Calculating SHA-256');
   const hash = await createSHA256(); hash.init();
   const reader = file.stream().getReader();
   try { while (true) { if (controller.signal.aborted) throw new Error('Transfer cancelled'); const chunk = await reader.read(); if (chunk.done) break; hash.update(chunk.value); } }
   finally { reader.releaseLock(); }
   const response = await request.post('/files', { ...values, name: file.name, size: file.size, sha256: hash.digest('hex') }, { signal: controller.signal });
   prepared = response.data.data as Grant;
   setPhase('Uploading to cloud storage');
   const headers = new Headers({ 'Content-Type': 'application/octet-stream' });
   for (const [name, values] of Object.entries(prepared.upload.headers)) {
    // The browser sets these transport headers from the URL and File body itself.
    if (!['host', 'content-length'].includes(name.toLowerCase())) headers.set(name, values.join(', '));
   }
   const put = await fetch(prepared.upload.url, { method: prepared.upload.method, headers, body: file, credentials: 'omit', redirect: 'error', signal: controller.signal });
   if (!put.ok) throw new Error(`Cloud upload failed (${put.status})`);
   setPhase('Target downloading and verifying');
   await request.post(`/files/${prepared.file.id}/deliver`, {}, { timeout: 330000, signal: controller.signal });
   Message.success('File delivered and SHA-256 verified');
  } catch (error) {
   // Fetch errors can embed the signed URL; never show that URL in notifications.
   Message.error(controller.signal.aborted ? 'Transfer interrupted. Check its status before retrying.' : prepared ? 'Transfer failed. Check the transfer status and storage CORS settings before retrying.' : (error as Error).message);
  } finally { active.current = null; setBusy(false); setPhase(''); await refresh().catch(() => undefined); }
 }
 async function remove(id: string) { try { await request.delete(`/files/${id}`); await refresh(); } catch (error) { Message.error((error as Error).message); } }
 return <Space direction="vertical" size="large" style={{ width: '100%' }}>
  <Card title="S3-compatible cloud storage">
   <Typography.Paragraph>Stage files in a private bucket, then let the selected SSH target download and verify them. Configure AWS S3 or a compatible storage endpoint.</Typography.Paragraph>
   {configured && <Alert type="warning" content="Saving storage settings invalidates outstanding upload preparations. Existing credentials are preserved when left blank." style={{ marginBottom: 20 }} />}
   <Form form={configForm} layout="vertical" style={{ maxWidth: 720 }}>
    <Form.Item field="enabled" label="Enabled" triggerPropName="checked"><Switch /></Form.Item>
    <Form.Item field="endpoint" label="S3 endpoint" rules={[{ required: true }]}><Input placeholder="https://s3.us-east-1.amazonaws.com" /></Form.Item>
    <Form.Item field="region" label="Region" rules={[{ required: true }]}><Input placeholder="us-east-1" /></Form.Item>
    <Form.Item field="bucket" label="Bucket" rules={[{ required: true }]}><Input /></Form.Item>
    <Form.Item field="prefix" label="Object prefix"><Input placeholder="connkit" /></Form.Item>
    <Form.Item field="access_key" label="Access key"><Input.Password autoComplete="new-password" placeholder={configured ? 'Leave blank to preserve' : ''} /></Form.Item>
    <Form.Item field="secret_key" label="Secret key"><Input.Password autoComplete="new-password" placeholder={configured ? 'Leave blank to preserve' : ''} /></Form.Item>
    <Form.Item field="session_token" label="Session token (optional)"><Input.Password autoComplete="new-password" /></Form.Item>
    <Form.Item field="clear_session_token" label="Clear saved session token" triggerPropName="checked"><Switch /></Form.Item>
    <Form.Item field="force_path_style" label="Use path-style addressing" triggerPropName="checked"><Switch /></Form.Item>
    <Form.Item field="allow_http" label="Allow an HTTP storage endpoint" extra="For explicitly trusted environments; HTTPS is required otherwise." triggerPropName="checked"><Switch /></Form.Item>
    <Form.Item field="proxy_id" label="Storage proxy (optional)"><Select allowClear options={proxies.map((proxy) => ({ label: proxy.name, value: proxy.id }))} /></Form.Item>
    <Form.Item field="max_file_size_mb" label="Maximum file size (MiB)"><InputNumber min={1} max={5120} /></Form.Item>
    <Button type="primary" loading={saving} disabled={busy} onClick={() => { void save(); }}>Save storage settings</Button>
   </Form>
  </Card>
  <Card title="Upload to target">
   <Alert type="info" content="Choose an SSH connection and an absolute Linux destination. Its parent directory must exist. Existing files are never overwritten. The target must be able to download from the storage endpoint." style={{ marginBottom: 20 }} />
   <Form form={uploadForm} layout="vertical" style={{ maxWidth: 720 }}>
    <Form.Item field="connection_id" label="SSH connection" rules={[{ required: true }]}><Select disabled={busy} options={connections.map((connection) => ({ label: connection.name, value: connection.id }))} /></Form.Item>
    <Form.Item field="destination" label="Destination path" rules={[{ required: true }]}><Input disabled={busy} placeholder="/absolute/path/file.zip" /></Form.Item>
    <Form.Item label="File"><input type="file" disabled={busy} onChange={(event) => setFile(event.target.files?.[0])} /></Form.Item>
    <Space><Button type="primary" disabled={!configured || !file} loading={busy} onClick={() => { void upload(); }}>Upload and deliver</Button>{busy && <Button onClick={() => active.current?.abort()}>Cancel</Button>}<Typography.Text>{phase}</Typography.Text></Space>
   </Form>
  </Card>
  <Card title="Recent transfers" extra={<Button onClick={() => { void refresh().catch((error: Error) => Message.error(error.message)); }}>Refresh</Button>}>
   <Table rowKey="id" data={transfers} scroll={{ x: 800 }} columns={[
    { title: 'File', dataIndex: 'name' }, { title: 'Connection', dataIndex: 'connection_id', width: 110 }, { title: 'Destination', dataIndex: 'destination' },
    { title: 'Status', dataIndex: 'status', render: (status: string) => <Tag color={status === 'delivered' ? 'green' : status === 'unknown' ? 'orange' : 'gray'}>{status}</Tag> },
    { title: 'Cloud object', width: 150, render: (_: unknown, transfer: Transfer) => <Popconfirm title="Delete only the cloud copy?" onOk={() => remove(transfer.id)}><Button disabled={['delivering', 'removed'].includes(transfer.status)} size="small">Remove cloud copy</Button></Popconfirm> }
   ]} />
  </Card>
 </Space>;
}
