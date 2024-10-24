import express, { Request } from 'express'
import { connect } from './database'
import bcrypt from 'bcrypt'
import jwt from 'jsonwebtoken'

const port = 3000
const app = express()
const secret = 'your_jwt_secret'

app.use(express.json())
app.use(express.static(__dirname + '/../public'))

app.post('/login', async (req, res) => {
  const db = await connect()
  const { email, password } = req.body
  const user = await db.get('SELECT * FROM users WHERE email = ?', [email])
  if (user && await bcrypt.compare(password, user.password)) {
    const token = jwt.sign({ id: user.id }, secret, { expiresIn: '1h' })
    res.json({ success: true, token })
  } else {
    res.json({ success: false })
  }
})

app.post('/users', async (req, res) => {
  const db = await connect()
  const { name, email, password } = req.body
  const hashedPassword = await bcrypt.hash(password, 10)
  const result = await db.run('INSERT INTO users (name, email, password) VALUES (?, ?, ?)', [name, email, hashedPassword])
  const user = await db.get('SELECT * FROM users WHERE id = ?', [result.lastID])
  res.json(user)
})

interface AuthenticatedRequest extends Request {
  userId?: number;
}

const authenticate = (req: AuthenticatedRequest, res: express.Response, next: express.NextFunction) => {
  const token = req.headers['authorization']
  if (!token) return res.sendStatus(401)
  jwt.verify(token, secret, (err, decoded) => {
    if (err) return res.sendStatus(403)
    req.userId = decoded.id
    next()
  })
}

app.put('/users/:id', authenticate, async (req, res) => {
  const db = await connect()
  const { name, email } = req.body
  const { id } = req.params
  if (req.userId !== parseInt(id)) return res.sendStatus(403)
  await db.run('UPDATE users SET name = ?, email = ? WHERE id = ?', [name, email, id])
  const user = await db.get('SELECT * FROM users WHERE id = ?', [id])
  res.json(user)
})

app.delete('/users/:id', authenticate, async (req, res) => {
  const db = await connect()
  const { id } = req.params
  if (req.userId !== parseInt(id)) return res.sendStatus(403)
  await db.run('DELETE FROM users WHERE id = ?', [id])
  res.sendStatus(204)
})

app.listen(port, () => {
  console.log(`Server running at http://localhost:${port}/`)
})