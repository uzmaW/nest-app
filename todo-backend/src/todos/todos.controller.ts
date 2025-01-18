import { Controller, Post, Body, Get, Param, ParseIntPipe,Put, Delete} from '@nestjs/common';
import { CreateTodoDto } from './dto/create-todo.dto';
import { UpdateTodoDto } from './dto/update-todo.dto';
import { Todo } from './entities/todo.entity';
import { TodosService } from './todos.service';


@Controller('todos')
export class TodosController {
    constructor(private readonly todosService: TodosService) {}
    
    @Post()
    async create(@Body() createTodoDto: CreateTodoDto): Promise<Todo> {
        return this.todosService.create(createTodoDto);
    }
    
    @Get()
    async findAll(): Promise<Todo[]> {
        return this.todosService.findAll();
    }

    @Get(':id')
    async findOne(@Param('id', ParseIntPipe) id: number): Promise<Todo> {
        return this.todosService.findOne(id);
    }

    @Put()
    async update(
        @Param('id', ParseIntPipe) id: number,
        @Body() updateTodoDto: UpdateTodoDto): Promise<Todo> {
        return this.todosService.update(id, updateTodoDto);
    }

    @Delete(':id')
    remove(@Param('id', ParseIntPipe) id: number): Promise<void> {
      return this.todosService.remove(id);
    }

}
