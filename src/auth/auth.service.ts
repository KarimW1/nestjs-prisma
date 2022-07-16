/* eslint-disable prettier/prettier */
import { ForbiddenException, Injectable } from '@nestjs/common';
import { PrismaService } from 'src/prisma/prisma.service';
import { AuthDto } from './dto/auth.dto';
import * as argon from 'argon2'
import { PrismaClientKnownRequestError } from '@prisma/client/runtime';
import { JwtService } from '@nestjs/jwt';
import { ConfigService } from '@nestjs/config';

@Injectable({})
export class AuthService {
  constructor(
                private prisma:PrismaService,
                private jwt:JwtService,
                private config:ConfigService){}

  async logIn(dto:AuthDto) {
    const user = await this.prisma.user.findUnique({
      where:{
        email:dto.email,
        }
      })

    if(!user){
      throw new ForbiddenException('Credentials token')
    }

    const PMatsh = await argon.verify(user.hash, dto.password)

    if(!PMatsh){
      throw new ForbiddenException('Credentials token')
    }

    delete(user.hash)
    return this.signToken(user.id, user.email)
  }
  // eslint-disable-next-line @typescript-eslint/no-empty-function
  async signUp(dto:AuthDto) {
    try{
      const hash = await argon.hash(dto.password);
      const user = await this.prisma.user.create({
        data:{
          firstName:dto.firstName,
          email: dto.email,
          hash,
        },
        select:{
          id:true,
          email:true,
          createdAt:true
        }
      })
      return this.signToken(user.id, user.email)
    }catch(err){
      if (err instanceof PrismaClientKnownRequestError){
        if(err.code === 'P2002'){
          throw new ForbiddenException('Credentials token')
        }
        throw err;
      }
    }
  }
  async signToken(
    userId:number,
    email:string
  ):Promise<{access_token:string}>{
    const payload = {
      sub:userId,
      email
    }

    const secret = this.config.get('JWT_SECRET')
    
   const token = await this.jwt.signAsync(payload, {
        expiresIn:'15m',
        secret:secret
    })

    return {access_token: token}
  }

}
