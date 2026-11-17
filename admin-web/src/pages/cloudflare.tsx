import { useEffect, useRef, useState } from 'react';
import { Alert, Button, Card, Modal, Space, Typography } from '@arco-design/web-react';
import { useI18n } from '../shared/i18n';
import { errorMessage } from '../shared/i18n/core';
import { request } from '../shared/api/request';

const flowKey = 'connkit.cloudflare.flow';
const callbackPath = '/oauth/cloudflare/callback';
type Status = { authorized: boolean; expires_at?: string; refreshable: boolean };

export function CloudflareAuthorization({ id, onClose }: { id: number; onClose: () => void }) {
 const { t } = useI18n();
 const [status, setStatus] = useState<Status>();
 const [busy, setBusy] = useState(false);
 const [error, setError] = useState('');
 async function refresh() {
  try { const { data } = await request.get(`/connections/${id}/oauth`); setStatus(data.data); setError(''); }
  catch (e) { setError(errorMessage(e)); }
 }
 useEffect(() => { void refresh(); }, [id]);
 async function login() {
  setBusy(true); setError('');
  try {
   const { data } = await request.post(`/connections/${id}/oauth/login`, { redirect_url: window.location.origin + callbackPath }, { timeout: 65000 });
   const url = new URL(data.data.authorization_url);
   if (url.protocol !== 'https:' || !(url.hostname === 'cloudflare.com' || url.hostname.endsWith('.cloudflare.com')) || !url.searchParams.get('state')) throw new Error(t('Invalid Cloudflare authorization URL'));
   sessionStorage.setItem(flowKey, JSON.stringify({ id, state: url.searchParams.get('state') }));
   window.location.assign(url.href);
  } catch (e) { setError(errorMessage(e)); setBusy(false); }
 }
 async function disconnect() {
  setBusy(true);
  try { await request.delete(`/connections/${id}/oauth`); await refresh(); }
  catch (e) { setError(errorMessage(e)); }
  finally { setBusy(false); }
 }
 return <Modal title={t('Cloudflare MCP authorization')} visible onCancel={onClose} footer={<Button onClick={onClose}>{t('Done')}</Button>}>
  <Typography.Paragraph>{t('Sign in on Cloudflare and select the account and permissions for this connection. Credentials are encrypted on the server.')}</Typography.Paragraph>
  {error && <Alert type="error" content={error} />}
  {status && <Alert type={status.authorized ? 'success' : 'info'} content={status.authorized ? t('Authorization saved. Test the connection, then verify domain and R2 access.') : t('Cloudflare login required')} />}
  <Space style={{ marginTop: 16 }}><Button type="primary" loading={busy} onClick={() => { void login(); }}>{t('Sign in / authorize')}</Button>{status?.authorized && <Button status="danger" disabled={busy} onClick={() => { void disconnect(); }}>{t('Disconnect authorization')}</Button>}</Space>
  <Typography.Paragraph style={{ marginTop: 16 }}>{t('Disconnect removes local credentials. Revoke the app in Cloudflare to remove its upstream grant.')}</Typography.Paragraph>
 </Modal>;
}

export function CloudflareCallback() {
 const { t } = useI18n();
 const started = useRef(false);
 const [error, setError] = useState('');
 useEffect(() => {
  if (started.current) return;
  started.current = true;
  const params = new URLSearchParams(window.location.search);
  window.history.replaceState(null, '', callbackPath);
  async function finish() {
   try {
    const saved = sessionStorage.getItem(flowKey);
    if (!saved) throw new Error(t('OAuth flow missing. Start authorization again.'));
    const flow = JSON.parse(saved) as { id: number; state: string };
    sessionStorage.removeItem(flowKey);
    if (params.get('state') !== flow.state) throw new Error(t('OAuth state mismatch. Start authorization again.'));
    if (params.has('error')) throw new Error(t('Cloudflare authorization was denied. Start authorization again.'));
    if (!params.get('code')) throw new Error(t('OAuth flow missing. Start authorization again.'));
    await request.post(`/connections/${flow.id}/oauth/callback`, { state: flow.state, code: params.get('code'), issuer: params.get('iss') || '' }, { timeout: 45000 });
    window.location.replace('/connections');
   } catch (e) { setError(errorMessage(e)); }
  }
  void finish();
 }, []);
 return <Card title={t('Cloudflare MCP authorization')}><Space direction="vertical">{error ? <Alert type="error" content={error} /> : <Typography.Text>{t('Completing Cloudflare authorization...')}</Typography.Text>}<Button onClick={() => window.location.replace('/connections')}>{t('Connections')}</Button></Space></Card>;
}
