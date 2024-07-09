function get_user_info() {
    var fs = require("fs");
    var stdinBuffer = fs.readFileSync(process.stdin.fd);
    var line = stdinBuffer.toString();
    console.log(line);
    line = line.replace(/(\r\n|\n|\r)/gm, "");
    return line
}

function get_new_id() {
    return Math.floor(Math.random() * 12345);
}

function connect_db() {
    const sqlite3 = require('sqlite3').verbose();
    const db = new sqlite3.Database(
        'users.sqlite',
        sqlite3.OPEN_READWRITE | sqlite3.OPEN_FULLMUTEX, 
        err => {
            if (err){
                console.log(err);
                throw err;
            } else {
                console.log('DB opened');
            }
        });

    return db;
}

function write_info(db, id, info) {
    db.serialize();
    const query = `INSERT INTO users VALUES (${id}, "${info}")`;
    console.log(query);
    db.exec(query);
    db.close();
}

let add_user = () => {
    console.log("Running add-user");
    var info = get_user_info();
    var id = get_new_id();
    var db = connect_db();
    write_info(db, id, info);
}

add_user()
