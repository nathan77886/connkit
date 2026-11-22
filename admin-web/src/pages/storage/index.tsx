import { useI18n, useFormLanguage } from '../../shared/i18n';
import { errorMessage, statusLabel } from '../../shared/i18n/core';
import { useEffect, useRef, useState } from 'react';
import { Alert, Button, Card, Form, Input, InputNumber, Message, Popconfirm, Select, Space, Switch, Table, Tag, Typography } from '@arco-design/web-react';
import { createSHA256 } from 'hash-wasm';
import type { MessageKey } from '../../shared/i18n/messages';
import { request } from '../../shared/api/request';

type Connection = { id: number; name: string; type: string; enabled: boolean };
type Transfer = { id: string; name: string; destination: string; status: string; connection_id: number; size: number };
type Grant = { file: Transfer; upload: { url: string; method: string; headers: Record<string, string[]> } };
type StorageProfile = { profile: string; enabled: boolean; endpoint: string; bucket: string; prefix: string };

export function StoragePage() {
 const { t } = useI18n();
 const [configForm] = Form.useForm();
 const [uploadForm] = Form.useForm();
 useFormLanguage(configForm);
 useFormLanguage(uploadForm);
 const [configured, setConfigured] = useState(false);
 const [profiles, setProfiles] = useState<StorageProfile[]>([]);
 const [profile, setProfile] = useState('default');
 const [saving, setSaving] = useState(false);
 const [busy, setBusy] = useState(false);
 const [phase, setPhase] = useState<MessageKey | ''>('');
 const [file, setFile] = useState<File>();
 const [connections, setConnections] = useState<Connection[]>([]);
 const [proxies, setProxies] = useState<{ id: number; name: string }[]>([]);
 const [transfers, setTransfers] = useState<Transfer[]>([]);
 const active = useRef<AbortController | null>(null);
 const fileInput = useRef<HTMLInputElement | null>(null);
 async function refresh() { const response = await request.get('/files'); setTransfers(response.data.data); }
 async function loadProfile(name: string) {
  const response = await request.get('/storage', { params: { profile: name } });
  setProfile(name); setConfigured(response.data.data.configured);
  configForm.setFieldsValue(response.data.data.config || { profile: name, enabled: true, region: 'us-east-1', prefix: 'connkit', force_path_style: true, max_file_size_mb: 512 });
 }
 useEffect(() => {
  let cancelled = false;
  void Promise.all([request.get('/storage/profiles'), request.get('/storage'), request.get('/connections'), request.get('/proxies'), request.get('/files')]).then(([profileResponse, storage, targets, routes, history]) => {
   if (cancelled) return;
   setProfiles(profileResponse.data.data); setConfigured(storage.data.data.configured);
   configForm.setFieldsValue(storage.data.data.config || { enabled: true, region: 'us-east-1', prefix: 'connkit', force_path_style: true, max_file_size_mb: 512 });
   setConnections(targets.data.data.filter((target: Connection) => target.type === 'ssh' && target.enabled));
   setProxies(routes.data.data); setTransfers(history.data.data);
  }).catch((error: Error) => { if (!cancelled) Message.error(errorMessage(error)); });
  return () => { cancelled = true; active.current?.abort(); };
 }, [configForm]);
 async function save() {
  const values = await configForm.validate(); setSaving(true);
  try { await request.put('/storage', { ...values, profile, proxy_id: values.proxy_id || null }); setConfigured(true); configForm.setFieldsValue({ access_key: '', secret_key: '', session_token: '', clear_session_token: false }); const listed = await request.get('/storage/profiles'); setProfiles(listed.data.data); Message.success(t('Cloud storage configuration saved')); }
  catch (error) { Message.error(errorMessage(error)); }
  finally { setSaving(false); }
 }
 async function upload() {
  if (!file || file.size === 0) { Message.error(t('Select a non-empty file')); return; }
  const values = await uploadForm.validate();
  setBusy(true); const controller = new AbortController(); active.current = controller;
  let prepared: Grant | undefined;
  try {
   setPhase('Calculating SHA-256');
   const hash = await createSHA256(); hash.init();
   const reader = file.stream().getReader();
   try { while (true) { if (controller.signal.aborted) throw new Error(t('Transfer cancelled')); const chunk = await reader.read(); if (chunk.done) break; hash.update(chunk.value); } }
   finally { reader.releaseLock(); }
   const response = await request.post('/files', { ...values, storage_profile: profile, name: file.name, size: file.size, sha256: hash.digest('hex') }, { signal: controller.signal });
   prepared = response.data.data as Grant;
   setPhase('Uploading to cloud storage');
   const headers = new Headers({ 'Content-Type': 'application/octet-stream' });
   for (const [name, values] of Object.entries(prepared.upload.headers)) {
    // The browser sets these transport headers from the URL and File body itself.
    if (!['host', 'content-length'].includes(name.toLowerCase())) headers.set(name, values.join(', '));
   }
   const put = await fetch(prepared.upload.url, { method: prepared.upload.method, headers, body: file, credentials: 'omit', redirect: 'error', signal: controller.signal });
   if (!put.ok) throw new Error(t('Cloud upload failed ({status})', { status: put.status }));
   setPhase('Target downloading and verifying');
   await request.post(`/files/${prepared.file.id}/deliver`, {}, { timeout: 330000, signal: controller.signal });
   Message.success(t('File delivered and SHA-256 verified'));
  } catch (error) {
   // Fetch errors can embed the signed URL; never show that URL in notifications.
   Message.error(controller.signal.aborted ? t('Transfer interrupted. Check its status before retrying.') : prepared ? t('Transfer failed. Check the transfer status and storage CORS settings before retrying.') : errorMessage(error));
  } finally { active.current = null; setBusy(false); setPhase(''); await refresh().catch(() => undefined); }
 }
 async function remove(id: string) { try { await request.delete(`/files/${id}`); await refresh(); } catch (error) { Message.error(errorMessage(error)); } }
 return <Space direction="vertical" size="large" style={{ width: '100%' }}>
  <Card title={t('S3-compatible cloud storage')}>
   <Typography.Paragraph>{t('Stage files in a private bucket, then let the selected SSH target download and verify them. Configure AWS S3 or a compatible storage endpoint.')}</Typography.Paragraph>
   {configured && <Alert type="warning" content={t('Saving storage settings invalidates outstanding upload preparations. Existing credentials are preserved when left blank.')} style={{ marginBottom: 20 }} />}
   <Form form={configForm} layout="vertical" style={{ maxWidth: 720 }}>
    <Form.Item label={t('Storage profile')}><Select value={profile} onChange={(value) => { void loadProfile(value); }} options={Array.from(new Set(['default', ...profiles.map((item) => item.profile)])).map((value) => ({ label: value, value }))} /></Form.Item>
    <Form.Item field="enabled" label={t('Enable')} triggerPropName="checked"><Switch /></Form.Item>
    <Form.Item field="endpoint" label={t('S3 endpoint')} rules={[{ required: true }]}><Input placeholder="https://s3.us-east-1.amazonaws.com" /></Form.Item>
    <Form.Item field="region" label={t('Region')} rules={[{ required: true }]}><Input placeholder="us-east-1" /></Form.Item>
    <Form.Item field="bucket" label={t('Bucket')} rules={[{ required: true }]}><Input /></Form.Item>
    <Form.Item field="prefix" label={t('Object prefix')}><Input placeholder="connkit" /></Form.Item>
    <Form.Item field="access_key" label={t('Access key')}><Input.Password autoComplete="new-password" placeholder={configured ? t('Leave blank to preserve') : ''} /></Form.Item>
    <Form.Item field="secret_key" label={t('Secret key')}><Input.Password autoComplete="new-password" placeholder={configured ? t('Leave blank to preserve') : ''} /></Form.Item>
    <Form.Item field="session_token" label={t('Session token (optional)')}><Input.Password autoComplete="new-password" /></Form.Item>
    <Form.Item field="clear_session_token" label={t('Clear saved session token')} triggerPropName="checked"><Switch /></Form.Item>
    <Form.Item field="force_path_style" label={t('Use path-style addressing')} triggerPropName="checked"><Switch /></Form.Item>
    <Form.Item field="allow_http" label={t('Allow an HTTP storage endpoint')} extra={t('For explicitly trusted environments; HTTPS is required otherwise.')} triggerPropName="checked"><Switch /></Form.Item>
    <Form.Item field="proxy_id" label={t('Storage proxy (optional)')}><Select allowClear options={proxies.map((proxy) => ({ label: proxy.name, value: proxy.id }))} /></Form.Item>
    <Form.Item field="max_file_size_mb" label={t('Maximum file size (MiB)')}><InputNumber min={1} max={5120} /></Form.Item>
    <Button type="primary" loading={saving} disabled={busy} onClick={() => { void save(); }}>{t('Save storage settings')}</Button>
   </Form>
  </Card>
  <Card title={t('Upload to target')}>
   <Alert type="info" content={t('Choose an SSH connection and an absolute Linux destination. Its parent directory must exist. Existing files are never overwritten. The target must be able to download from the storage endpoint.')} style={{ marginBottom: 20 }} />
   <Form form={uploadForm} layout="vertical" style={{ maxWidth: 720 }}>
    <Form.Item field="connection_id" label={t('SSH connection')} rules={[{ required: true }]}><Select disabled={busy} options={connections.map((connection) => ({ label: connection.name, value: connection.id }))} /></Form.Item>
    <Form.Item field="destination" label={t('Destination path')} rules={[{ required: true }]}><Input disabled={busy} placeholder="/absolute/path/file.zip" /></Form.Item>
    <Form.Item label={t('File')}><Space><Button disabled={busy} onClick={() => fileInput.current?.click()}>{t('Choose file')}</Button><Typography.Text>{file?.name || t('No file selected')}</Typography.Text><input ref={fileInput} type="file" hidden disabled={busy} aria-label={t('Choose file')} onChange={(event) => setFile(event.target.files?.[0])} /></Space></Form.Item>
    <Space><Button type="primary" disabled={!configured || !file} loading={busy} onClick={() => { void upload(); }}>{t('Upload and deliver')}</Button>{busy && <Button onClick={() => active.current?.abort()}>{t('Cancel')}</Button>}<Typography.Text>{phase ? t(phase) : ''}</Typography.Text></Space>
   </Form>
  </Card>
  <Card title={t('Recent transfers')} extra={<Button onClick={() => { void refresh().catch((error: Error) => Message.error(errorMessage(error))); }}>{t('Refresh')}</Button>}>
   <Table rowKey="id" data={transfers} scroll={{ x: 800 }} columns={[
    { title: t('File'), dataIndex: 'name' }, { title: t('Connection'), dataIndex: 'connection_id', width: 110 }, { title: t('Destination'), dataIndex: 'destination' },
    { title: t('Status'), dataIndex: 'status', render: (status: string) => <Tag color={status === 'delivered' ? 'green' : status === 'unknown' ? 'orange' : 'gray'}>{statusLabel(status)}</Tag> },
    { title: t('Cloud object'), width: 150, render: (_: unknown, transfer: Transfer) => <Popconfirm title={t('Delete only the cloud copy?')} onOk={() => remove(transfer.id)}><Button disabled={['delivering', 'removed'].includes(transfer.status)} size="small">{t('Remove cloud copy')}</Button></Popconfirm> }
   ]} />
  </Card>
 </Space>;
}
