#!/usr/bin/env bash
set -e
mkdir -p assets
cat > index.html <<'H'
<!doctype html>
<html><head><title>Asha — Portfolio</title><link rel="stylesheet" href="style.css"></head>
<body><h1>Hi, I'm Asha</h1><p>Frontend developer.</p>
<a href="mailto:asha@example.com">Contact</a>
<img src="assets/me.jpg">
<script src="script.js"></script></body></html>
H
printf 'body{font-family:sans-serif;max-width:720px;margin:auto}\n' > style.css
printf 'document.querySelector("h1").addEventListener("click",()=>alert("hi"));\n' > script.js
