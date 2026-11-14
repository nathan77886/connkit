import React from 'react';
import ReactDOM from 'react-dom/client';
import '@arco-themes/react-arco-pro/css/arco.css';
import './app/styles/theme-tokens.less';
import './app/styles/global.less';
import { App } from './app/App';

ReactDOM.createRoot(document.getElementById('root')!).render(<React.StrictMode><App /></React.StrictMode>);
