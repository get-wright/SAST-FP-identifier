import { Request, Response } from "express";
import axios from "axios";

function processRequest(req: Request): string {
    const query = `SELECT * FROM users WHERE id = '${req.params.id}'`;
    return query;
}

const validateInput = (input: string): boolean => {
    return input.length > 0;
};

class UserService {
    async getUser(id: number): Promise<string> {
        const result = await axios.get(`/api/users/${id}`);
        return result.data;
    }

    private sanitize(value: string): string {
        return value.trim();
    }
}
