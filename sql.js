import "dotenv/config";
import mysql from 'mysql2';

let connection = mysql.createConnection({
    host: process.env.DB_HOST + ":" + process.env.DB_PORT,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWD,
    database: process.env.DB_USER
});

connection.connect(err => {
    if(err){
        console.error('Error connecting: ', err.stack);
    }
    console.log('Connected');
});

await connection.execute(`
    CREATE TABLE IF NOT EXISTS users (
        uuid INT AUTO_INCREMENT PRIMARY KEY UNIQUE,
        username VARCHAR(100) UNIQUE,
        email VARCHAR(100) UNIQUE,
        public_key VARCHAR(100),
        private_key_hash VARCHAR(100),
        token VARCHAR(100),
        selfhost_ip VARCHAR(100),
        selfhost_port VARCHAR(100),
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
`);
console.log("Table 'users' ensured.");

async function addUser(email, name, publicKey, selfhostIP){
    const [result] = await connection.execute(`INSERT INTO users (name, email, publicKey, selfhostIP) VALUES (?, ?, ?, ?)`, [name, email, publicKey, selfhostIP])
    console.log(`Inserted user with ID: ${result.insertId}`)
}
async function changeName(email, newName) {
  const updateQuery = `UPDATE users SET name = ? WHERE email = ?`;
  const [result] = await connection.execute(updateQuery, [newName, email]);

  console.log(`Updated ${result.affectedRows} row(s)`);
}
async function changeEmail(email, newEmail) {
  const updateQuery = `UPDATE users SET email = ? WHERE email = ?`;
  const [result] = await connection.execute(updateQuery, [newEmail, email]);

  console.log(`Updated ${result.affectedRows} row(s)`);
}

function closeConnection(){
    connection.end();
}

addUser('some@email.com', 'Gußtaf','public','10.209.56.20');
changeName('some@email.com', 'Gustav');
changeEmail('gustav@gußtafson.com')

closeConnection();