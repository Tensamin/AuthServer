let express = require('express')
let app = express()
let dotenv = require('dotenv')
let mysql = require('mysql')
dotenv.config()

let database = mysql.createConnection({
    host: process.env.DB_HOST,
    port: Number(process.env.DB_PORT),
    user: process.env.DB_USER,
    password: process.env.DB_PASSWD,
    database: process.env.DB_DATABASE
})

database.connect(function(err) {
  if (err) throw err;
  console.log("Connected!");
  let sql = "CREATE TABLE customers (name VARCHAR(255), address VARCHAR(255))";

  database.query(sql, function (err, result) {
    if (err) throw err;
    console.log("Table created");
  });
});

// Name, Birthday, Email, Public Key, Private Key, Password Hash

console.log("cum")