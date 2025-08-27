// TypeScript sample file for testing
interface User {
    id: number;
    name: string;
    email: string;
}

class UserService {
    private users: User[] = [];

    constructor() {
        console.log("UserService initialized");
    }

    public addUser(user: User): void {
        this.users.push(user);
    }

    public getUser(id: number): User | undefined {
        return this.users.find(user => user.id === id);
    }

    public getAllUsers(): User[] {
        return [...this.users];
    }

    private validateUser(user: User): boolean {
        return user.id > 0 && user.name.length > 0 && user.email.includes('@');
    }
}

function createUser(name: string, email: string): User {
    return {
        id: Math.floor(Math.random() * 1000),
        name,
        email
    };
}

export { User, UserService, createUser };
