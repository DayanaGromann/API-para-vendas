import { getCustomRepository } from "typeorm";
import UsersRepository  from "../typeorm/repositories/UsersRepository";
import User from "../typeorm/entities/User";

class ListUsersService {
	public async execute(): Promise<User[]>{
			const usersRepository = getCustomRepository(UsersRepository);

			const users = await usersRepository.find();

			return users;
	}
}

export default ListUsersService;
