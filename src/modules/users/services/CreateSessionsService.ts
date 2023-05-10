import AppError from '@shared/errors/AppError';
import { getCustomRepository } from 'typeorm';
import User from '../typeorm/entities/User';
import { UsersRepository } from '../typeorm/repositories/UsersRepository';
import { compare, hash } from 'bcryptjs';
import { sign } from 'jsonwebtoken';

interface IRequest {
	email: string;
	password: string;
}

interface IResponse {
	user: User;
}

interface IResponse {
	user: User;
	token: string;
}

class CreateSessionsService {
	public async execute({ email, password }: IRequest): Promise<IResponse> {
		const usersRepository = getCustomRepository(UsersRepository);
		const user = await usersRepository.findByEmail(email);

		if (!user) {
			throw new AppError('Incorrect e-mail/password combination', 401);
		}

		const passwordConfirmed = await compare(password, user.password)

		if (!passwordConfirmed) {
			throw new AppError('Incorrect e-mail/password combination', 401);
		}

		const token = sign({}, '7b5b464966df68dbb6ec5e4a42510118', {
			subject: user.id,
			expiresIn: '1d',
		})
		return {user, token};
	}
}

export default CreateSessionsService;
