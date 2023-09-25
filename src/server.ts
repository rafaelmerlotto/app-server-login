import express from 'express'
import { prisma } from './prisma'

const server = express()
server.use(express.json())


server.post('/login', async (req, res) => {
    const body = req.body
    try {
        const user = await prisma.user.findUnique({
            where: {
                email: body.email
            }
        })
        res.status(201).send(`Hello ${user?.name}`)
    }catch{
        res.status(403).send({ msg: 'Invalid authentication' })
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