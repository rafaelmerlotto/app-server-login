import express from 'express'
import { prisma } from './prisma'
import { User } from '@prisma/client'
import { compareSync, hashSync } from 'bcrypt'
import jwt from 'jsonwebtoken';
import { getJwtKeys } from './key';

const server = express()
server.use(express.json())


async function verifyUser(email: string, password: string): Promise<User | null> {
    const user = await prisma.user.findUnique({
        where: {
            email: email
        }
    })
    if (!user) {
        return null
    }
    if (!compareSync(password, user.password)) {
        return null
    }
    return user
}


async function generateJwt(user: User): Promise<string> {
    const payload = {
        aud: 'access',
        id: user.id,
        email: user.email
    }
    const { privateKey } = await getJwtKeys();
    return jwt.sign(payload, privateKey, { algorithm: 'RS256' })
}

server.post('/login', async (req, res) => {
    const { email, password } = req.body
    const user = await verifyUser(email, password)
    if (!user) {
        res.status(403).send({ msg: 'Invalid authentication' })
    }
    const token = await generateJwt(user!);
    return res.status(201).send({
        accessToken: token
    })
})


server.post('/register', async (req, res) => {
    const { name, email, password } = req.body;
    const passwordHash = hashSync(password, 5);
    let user: User;
    try {
        user = await prisma.user.create({
            data: {
                email: email,
                name: name,
                password: passwordHash
            }
        })
        return res.status(201).send({
            id: user.id,
            email: user.email,
            name: user.name
        })
    } catch {
        return res.status(401).send({ msg: 'cannot create user' })
    }

})

server.get('/', async (req, res) => {
    try {
        const users = await prisma.user.findMany()
        res.status(200).send(users)
    } catch {
        res.status(404).send({ msg: 'Cannot find user' })
    }
})


const PORT = 3001
server.listen(PORT, () => {
    console.log(`server is running on 🚀 http://localhost:${PORT}`)
})