import axios from 'axios';

// Same API envelope and centralized request interception as the Admin scaffold.
export const request = axios.create({ baseURL: '/api/v1', timeout: 15000 });
request.interceptors.request.use((config) => {
 const token = sessionStorage.getItem('connkit.admin.token');
 if (token) config.headers.Authorization = `Bearer ${token}`;
 return config;
});
request.interceptors.response.use((response) => {
 if (response.data.code !== 0) throw new Error(response.data.message || 'Request failed');
 return response;
}, (error) => {
 if (error.response?.status === 401 && !error.config?.url?.endsWith('/auth/login')) {
  sessionStorage.removeItem('connkit.admin.token');
  window.location.assign('/login');
 }
 return Promise.reject(new Error(error.response?.data?.message || error.message || 'Request failed'));
});
