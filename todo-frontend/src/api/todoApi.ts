import axios from 'axios';
import { Todo } from '../types/todo';

const api = axios.create({
  baseURL: import.meta.env.REACT_APP_API_URL || 'http://localhost:3000',
});

api.interceptors.request.use((config) => {
  const token = localStorage.getItem('token');
  if (token) {
    config.headers.Authorization = `Bearer ${token}`;
  }
  return config;
});

export const todoApi = {
  login: (email: string, password: string) =>
    api.post('/auth/login', { email, password }),
  
  getTodos: () => api.get<Todo[]>('/todos'),
  
  createTodo: (todo: { title: string; description: string }) =>
    api.post<Todo>('/todos', todo),
  
  updateTodo: (id: number, todo: Partial<Todo>) =>
    api.put<Todo>(`/todos/${id}`, todo),
  
  deleteTodo: (id: number) => api.delete(`/todos/${id}`),
};