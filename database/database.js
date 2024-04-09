const mysql = require('mysql2/promise');

const db = mysql.createPool({
    host: 'restaurantexplorerdb.c542uag6s6d9.us-east-1.rds.amazonaws.com',
    user: 'root',
    password: 'password',
    database: 'restaurantexplorerdb'
});

module.exports.db = db;
