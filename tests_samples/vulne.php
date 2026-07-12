<?php

// Injection SQL par concaténation
$id = $_GET['id'];
$query = "SELECT * FROM users WHERE id = " . $id;
mysql_query($query);

// XSS echo direct superglobale
echo $_GET['name'];

// XSS echo variable sans échappement
$username = $_POST['username'];
echo $username;

// Injection de commande
$file = $_GET['file'];
system($file);

// eval() avec variable
$code = $_POST['code'];
eval($code);

// Inclusion de fichier avec variable
$page = $_GET['page'];
include($page);

// Exécution backticks
$cmd = $_GET['cmd'];
$output = `$cmd`;

// unserialize sur entrée utilisateur 
$data = unserialize($_COOKIE['session']);

// Secret hardcodé
$api_key = "sk-prod-12345ABCDE";

// md5 pour mot de passe
$hashed = md5($password);

// display_errors en production
ini_set('display_errors', '1');

$safe = htmlspecialchars($_GET['safe']);
echo $safe;
$safeQuery = "SELECT * FROM products";
