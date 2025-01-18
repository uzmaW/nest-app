import { Injectable } from '@nestjs/common';
import { Todo } from './entities/todo.entity';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { CreateTodoDto } from './dto/create-todo.dto';
import { UpdateTodoDto } from './dto/update-todo.dto';

@Injectable()
export class TodosService {
   
    constructor(
        @InjectRepository(Todo)
        private todosRepository: Repository<Todo>,
    ) 
    {
        console.log('TodosService');
    }

    findAll(): Promise<Todo[]> {
        return this.todosRepository.find();
    }
    async findOne(id: number): Promise<Todo> {
        const todo = await this.todosRepository.findOne({
            where: {id}
        });
        
        if(!todo)
            throw new Error('Todo not found');
        
        return todo;
    }

    async remove(id: number): Promise<void> {
        const todo = await this.todosRepository.findOne({
            where: {id}
        });
        await this.todosRepository.delete(todo);
    }

    async create(createTodoDto: CreateTodoDto): Promise<Todo> {
        const todo = this.todosRepository.create(createTodoDto);
        return await this.todosRepository.save(todo);
      }
    
      async update(id:number, updateTodoDto: UpdateTodoDto): Promise<Todo> {
        const todo = await this.todosRepository.findOne({
            where: {id}
        });
        if(!todo)
            throw new Error('Todo not found');
        const updatedTodo = Object.assign(todo, updateTodoDto);  

        return this.todosRepository.save(updatedTodo);
    }
}
