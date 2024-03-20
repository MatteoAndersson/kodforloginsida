const express = require("express");
const mysql = require("mysql2");
const dotenv = require("dotenv");
const path = require("path");
const bcrypt = require("bcryptjs");

const app = express();
app.set('view engine', 'hbs')
dotenv.config({path: "./.env"});

const publicDir = path.join(__dirname, './webbsidan')

const db = mysql.createConnection({
    // värden hämtas från .env
    host: process.env.DATABASE_HOST,
    user: process.env.DATABASE_USER,
    password: process.env.DATABASE_PASSWORD,
    database: process.env.DATABASE
});

app.use(express.urlencoded({extended: 'false'}))
app.use(express.json())

db.connect((error) => {
    if(error){
        console.log(error);
    } else{
        console.log("Ansluten till MySQL");
    }
});

// Använder mallen index.hbs
app.get("/", (req, res) => {
    res.render("index");
});

// Använder mallen register.hbs
app.get("/register", (req, res) => {
    res.render("register");
});

// Använder mallen login.hbs
app.get("/login", (req, res) => {
    res.render("login");
});


//egen ändring
function isValidEmail(email) {
    // Regex för att kontrollera epostadressens format
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    return emailRegex.test(email);
}





// Tar emot poster från registeringsformuläret
app.post("/auth/register", async (req, res) => {    
    const { name, email, password, password_confirm } = req.body
    if (password !== password_confirm){
        // egen ändring som kollar om båda lösen är samma
        return res.render('register', {
            message: 'Lösenorden matchar inte'
        })
    }
    if (!name || !email || !password || !password_confirm){
        // egen ändring som kollar om något fällt inte är ifyllt
        return res.render('register', {
            message: 'Alla fält är inte ifyllda'
        })
    }
    if (!isValidEmail(email)) {
        // egen ändring som hanterar fallet där epostadressen inte är i rätt format med hjälp av den tidigare funktionen
        return res.render('register', { message: 'Ej giltig e-postadress' });
    } 


    // alla dessa 4 if statements nedan är för att kolla att password skrivs på rätt sätt
    if (password.length < 8) {
        // Minst 8 tecken krävs
        return res.render('register', { message: 'Lösenordet måste innehålla minst 8 tecken med minst en siffra, en liten bokstav och en stor bokstav' });
    }

    if (!/\d/.test(password)) {
        // Minst en siffra krävs
        return res.render('register', { message: 'Lösenordet måste innehålla minst 8 tecken med minst en siffra, en liten bokstav och en stor bokstav' });
    }

    if (!/[a-z]/.test(password)) {
        // Minst en liten bokstav krävs
        return res.render('register', { message: 'Lösenordet måste innehålla minst 8 tecken med minst en siffra, en liten bokstav och en stor bokstav' });
    }

    if (!/[A-Z]/.test(password)) {
        // Minst en stor bokstav krävs
        return res.render('register', { message: 'Lösenordet måste innehålla minst 8 tecken med minst en siffra, en liten bokstav och en stor bokstav' });
    }
    try {
        const hashedPassword = await bcrypt.hash(password, 10); //hashedPassword är det krypterade lösenordet
    
        // Kontrollera om namnet redan finns i databasen
        const nameExists = await new Promise((resolve, reject) => {
            db.query('SELECT name FROM users WHERE name = ?', [name], (error, result) => {
                if (error) {
                    reject(error);
                } else {
                    resolve(result.length > 0);// Om result är 1 eller mer finns namnet redan i databasen och nameExists blir True och då visar meddelandet "Namnet är upptaget som står 6 rader ner i koden."
                }
            });
        });
    
        if (nameExists) {
            return res.render('register', { message: 'Namnet är upptaget' });
        }
    
        // Kontrollera om epostadressen redan finns i databasen samma sätt som med namn
        const emailExists = await new Promise((resolve, reject) => {
            db.query('SELECT email FROM users WHERE email = ?', [email], (error, result) => {
                if (error) {
                    reject(error);
                } else {
                    resolve(result.length > 0);
                }
            });
        });
    
        if (emailExists) {
            return res.render('register', { message: 'Email är upptaget' });
        }
    
        // Fortsätt med registreringsprocessen om namnet och epostadressen inte finns i databasen
        //lägg till användaren
        db.query('INSERT INTO users SET ?', {name: name, email: email, password: hashedPassword}, (err, result) => {//password sätts till hashedPassword för att lösenordet ska stå som det krypterade lösenordet
            if (err) {
                console.log(err);
                return res.render('register', { message: 'Registrering misslyckades' });
            } else {
                return res.render('register', { message: 'Användare registrerad' });
            }
        });
    } catch (error) {
        console.log(error);
        return res.render('register', { message: 'Något gick fel' });
    }
})

// Tar emot poster från loginsidan
app.post("/auth/login", (req, res) => {   
    const { name, password } = req.body

    
    //kollar om namnet finns
    db.query('SELECT name, password FROM users WHERE name = ?', [name], async (error, result) => {
        if(error){
            console.log(error)
        }
        // Om == 0 så finns inte användaren
        if( result.length == 0 ) {
            return res.render('login', {
                message: "Användaren finns ej"
            })
        }
        const hashedPassword = result[0].password;

        try {
            const passMatch = await bcrypt.compare(password, hashedPassword);//om det krypterade lösenordet matchar med det som står utan kryptering så loggas man in
        
            // Kollar om lösenordet matchar det i databasen
            if (passMatch) {
                return res.render('login', {
                    message: "Du är nu inloggad"
                })
           } 
           else {
                return res.render('login', {
                    message: "Fel lösenord"
                })
           }
        } catch (error){
            console.log(error)
        }
    })
})

// Körde på 4k här bara för att skilja mig åt
// från server.js vi tidigare kört som använder 3k
app.listen(4000, ()=> {
    console.log("Servern körs, besök http://localhost:4000")
})