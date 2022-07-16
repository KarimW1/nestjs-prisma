/* eslint-disable prettier/prettier */
import { Controller, Get, HttpCode, HttpStatus, UseGuards } from '@nestjs/common';
import { User } from '@prisma/client';

import { GetUser } from 'src/decorators';
import { JwtGuard } from '../guards';

@UseGuards(JwtGuard)
@Controller('users')
export class UserController {

    @Get('me')
    getMe(@GetUser() user:User){
        return user
    }

}
