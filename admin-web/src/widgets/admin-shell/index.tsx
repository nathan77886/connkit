import { useEffect, useState, type PropsWithChildren } from 'react';
import { Button, Layout, Menu, Space, Typography } from '@arco-design/web-react';
import { useLocation, useNavigate } from 'react-router-dom';
import { request } from '../../shared/api/request';
import changeTheme from '../../shared/lib/changeTheme';

const items = [{ key: 'connections', label: 'Connections' }, { key: 'proxies', label: 'Proxies' }, { key: 'keys', label: 'API keys' }, { key: 'storage', label: 'Cloud storage' }, { key: 'calls', label: 'Tool calls' }, { key: 'access', label: 'Access policy' }];

// Adapted from the existing Arco Admin shell: fixed navigation and theme-aware content.
export function AdminShell({ children }: PropsWithChildren) {
 const navigate = useNavigate();
 const location = useLocation();
 const [theme, setTheme] = useState(localStorage.getItem('connkit.theme') || 'light');
 useEffect(() => { changeTheme(theme); localStorage.setItem('connkit.theme', theme); }, [theme]);
 async function logout() {
  try { await request.post('/auth/logout'); } finally { sessionStorage.removeItem('connkit.admin.token'); navigate('/login'); }
 }
 return <Layout className="admin-shell">
  <Layout.Sider breakpoint="lg" collapsible width={220}>
   <div className="brand">ConnKit</div>
   <Menu selectedKeys={[location.pathname.split('/')[1]]} onClickMenuItem={(key) => navigate(`/${key}`)}>
    {items.map((item) => <Menu.Item key={item.key}>{item.label}</Menu.Item>)}
   </Menu>
  </Layout.Sider>
  <Layout>
   <Layout.Header className="admin-header"><Typography.Text>Connection management</Typography.Text><Space><Button onClick={() => setTheme(theme === 'light' ? 'dark' : 'light')}>Theme</Button><Button onClick={() => { void logout(); }}>Sign out</Button></Space></Layout.Header>
   <Layout.Content className="admin-content">{children}</Layout.Content>
  </Layout>
 </Layout>;
}
