require('dotenv').config();
const express = require('express');
const session = require('express-session');
const bcrypt = require('bcryptjs');
const massive = require('massive');

const app = express();

app.use(express.json());

let { SERVER_PORT, CONNECTION_STRING, SECRET } = process.env;

app.use(
  session({
    secret: SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: {
      maxAge: 1000 * 60 * 60
    }
  })
);

massive(CONNECTION_STRING).then(db => { // this db references the second db on the next line
  app.set('db', db);
});

app.post('/auth/signup' , async (req,res) => { ///this creates a new user and stores the hash in the server
  const {email,password} = req.body  // pulling the email and password off of the boy
  const db = req.app.get('db')
  const foundUser = await db.check_user_exists(email)
  if(foundUser[0]) return res.status(409).send('Email taken')//the [0] is there becuase an array is always returned even if it is a single item, a single item is at position 0
  const salt = bcrypt.genSaltSync(10)
  const hash = bcrypt.hashSync(password,salt)
  const newUser = await db.create_user([email,hash])
  req.session.user = {id: newUser[0].id, email: newUser[0].email }
  res.status(200).send(req.session.user)
})

app.post('/auth/login' , async (req,res) => {  //lets an existing user log in. 
  const {email,password} = req.body
  const db = req.app.get('db')
  const foundUser = await db.check_user_exists(email)
  if(!foundUser[0]) return res.status(409).send('Incorrect Email')
  const authenticated = bcrypt.compareSync(password,foundUser[0].user_password)
  if(authenticated){
    req.session.user = {id: foundUser[0].id,email: foundUser[0].email}
    res.status(200).send(req.session.user)
  } else {
    res.status(401).send('Incorrect Email or password')  // don't say just one or the other, that would give a potential hacker a clue what they need to do next.
  }
})

app.get('/auth/logout' , (req,res) => {
  req.session.destroy()
  res.sendStatus(200)
})

app.get('/auth/user'), (req,res) => {
  if(req.session.user){
    res.status(200).send(req.session.user)
  } else {
    res.status(401).send('Please log in')
  }
}

app.listen(SERVER_PORT, () => {
  console.log(`Listening on port: ${SERVER_PORT}`);
});
