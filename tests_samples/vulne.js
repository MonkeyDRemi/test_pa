
// XSS via innerHTML
const userInput = document.querySelector("#search").value;
document.getElementById("result").innerHTML = userInput;

// XSS via document.write
const param = new URLSearchParams(window.location.search).get("q");
document.write("<h1>" + param + "</h1>");

// Injection de code via eval
const formula = prompt("Entrez une formule :");
const result  = eval(formula);

//Injection via new Function
const fn = new Function("x", "return " + userInput);

//setTimeout avec variable
const code = "alert('hack')";
setTimeout(code, 1000);

// Injection SQL côté serveur (Node/Express)
const userId = req.params.id;
const query  = "SELECT * FROM users WHERE id = " + userId;
db.execute(query);

// SQL via template
const name = req.body.name;
db.query(`SELECT * FROM products WHERE name = '${name}'`);

//Open Redirect
const next = req.query.redirect;
window.location = next;

//Accès cookie 
const token = document.cookie;

// localStorage avec donnée sensible
localStorage.setItem("token", authToken);

document.getElementById("title").innerHTML = "<strong>Bienvenue</strong>";
document.write("Page chargée.");
setTimeout(function() { console.log("ok"); }, 500);
const safeQuery = "SELECT * FROM products";
