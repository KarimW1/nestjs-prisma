/* eslint-disable prettier/prettier */
import { Module } from '@nestjs/common';
import { AuthController } from './auth.controller';
import { AuthService } from './auth.service';
import { PrismaModule } from '../prisma/prisma.module'
import { JwtModule } from '@nestjs/jwt';
import { JwtStratgy } from '../strategy';

@Module({
  imports:[PrismaModule, JwtModule.register({})],
  controllers: [AuthController],
  providers: [AuthService, JwtStratgy],
})
export class AuthModule {}
