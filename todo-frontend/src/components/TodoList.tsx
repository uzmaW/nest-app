import React, { useState, useEffect } from 'react';
import { Todo } from '../types/todo';
import { todoApi } from '../api/todoApi';

export const TodoList = () => {
  const [todos, setTodos] = useState<Todo[]>([]);
  const [newTodo, setNewTodo] = useState({ title: '', description: '' });
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    loadTodos();
  }, []);

  const loadTodos = async () => {
    try {
      setIsLoading(true);
      setError(null);
      const response = await todoApi.getTodos();
      setTodos(response.data);
    } catch (err) {
      setError('Failed to load todos');
    } finally {
      setIsLoading(false);
    }
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!newTodo.title.trim()) {
      setError('Title is required');
      return;
    }
    try {
      setIsLoading(true);
      setError(null);
      await todoApi.createTodo(newTodo);
      setNewTodo({ title: '', description: '' });
      await loadTodos();
    } catch (err) {
      setError('Failed to create todo');
    } finally {
      setIsLoading(false);
    }
  };

  if (isLoading) {
    return (
      <div className="flex justify-center items-center min-h-screen">
        <div className="animate-spin rounded-full h-12 w-12 border-t-2 border-b-2 border-primary-600"></div>
      </div>
    );
  }

  return (
    <div className="max-w-4xl mx-auto p-4 space-y-6">
      {error && (
        <div className="bg-red-50 border border-red-200 text-red-700 px-4 py-3 rounded relative">
          {error}
          <button 
            onClick={() => setError(null)}
            className="absolute top-0 right-0 p-4"
          >
            ×
          </button>
        </div>
      )}

      <form onSubmit={handleSubmit} className="card space-y-4">
        <h2 className="text-2xl font-bold text-gray-800">Add New Todo</h2>
        <div>
          <label htmlFor="title" className="block text-sm font-medium text-gray-700 mb-1">
            Title
          </label>
          <input
            id="title"
            type="text"
            value={newTodo.title}
            onChange={(e) => setNewTodo({ ...newTodo, title: e.target.value })}
            placeholder="Enter todo title"
            className="input"
          />
        </div>
        <div>
          <label htmlFor="description" className="block text-sm font-medium text-gray-700 mb-1">
            Description
          </label>
          <textarea
            id="description"
            value={newTodo.description}
            onChange={(e) => setNewTodo({ ...newTodo, description: e.target.value })}
            placeholder="Enter description"
            className="input min-h-[100px]"
          />
        </div>
        <button
          type="submit"
          disabled={isLoading}
          className="btn-primary w-full disabled:opacity-50 disabled:cursor-not-allowed"
        >
          {isLoading ? 'Adding...' : 'Add Todo'}
        </button>
      </form>

      <div className="space-y-4">
        {todos.map((todo) => (
          <div key={todo.id} className="card hover:shadow-lg transition-shadow">
            <div className="flex items-center justify-between">
              <div className="flex items-center space-x-3">
                <input
                  type="checkbox"
                  checked={todo.isCompleted}
                  onChange={async () => {
                    try {
                      await todoApi.updateTodo(todo.id, {
                        isCompleted: !todo.isCompleted,
                      });
                      loadTodos();
                    } catch (err) {
                      setError('Failed to update todo');
                    }
                  }}
                  className="h-4 w-4 text-primary-600 focus:ring-primary-500 border-gray-300 rounded"
                />
                <h3 className={`text-lg font-semibold ${
                  todo.isCompleted ? 'text-gray-400 line-through' : 'text-gray-800'
                }`}>
                  {todo.title}
                </h3>
              </div>
              <button
                onClick={async () => {
                  try {
                    await todoApi.deleteTodo(todo.id);
                    loadTodos();
                  } catch (err) {
                    setError('Failed to delete todo');
                  }
                }}
                className="text-red-500 hover:text-red-700 transition-colors"
              >
                Delete
              </button>
            </div>
            <p className={`mt-2 ${
              todo.isCompleted ? 'text-gray-400' : 'text-gray-600'
            }`}>
              {todo.description}
            </p>
            <div className="mt-2 text-sm text-gray-500">
              Created: {new Date(todo.createdAt).toLocaleDateString()}
            </div>
          </div>
        ))}
      </div>
    </div>
  );
};